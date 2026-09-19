package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/valt-dev/valt/server/internal/admin"
	"github.com/valt-dev/valt/server/internal/agent"
	"github.com/valt-dev/valt/server/internal/audit"
	"github.com/valt-dev/valt/server/internal/auth"
	"github.com/valt-dev/valt/server/internal/billing"
	"github.com/valt-dev/valt/server/internal/integration"
	"github.com/valt-dev/valt/server/internal/config"
	"github.com/valt-dev/valt/server/internal/consent"
	"github.com/valt-dev/valt/server/internal/database"
	"github.com/valt-dev/valt/server/internal/dynsecret"
	"github.com/valt-dev/valt/server/internal/gateway"
	custommiddleware "github.com/valt-dev/valt/server/internal/middleware"
	"github.com/valt-dev/valt/server/internal/notify"
	"github.com/valt-dev/valt/server/internal/rbac"
	"github.com/valt-dev/valt/server/internal/org"
	"github.com/valt-dev/valt/server/internal/policy"
	"github.com/valt-dev/valt/server/internal/project"
	"github.com/valt-dev/valt/server/internal/ratelimit"
	"github.com/valt-dev/valt/server/internal/scanner"
	"github.com/valt-dev/valt/server/internal/usage"
	"github.com/valt-dev/valt/server/internal/vault"
	"github.com/valt-dev/valt/server/internal/webhooks"
	"github.com/valt-dev/valt/server/internal/workflow"
	"github.com/valt-dev/valt/server/internal/workspace"
	"github.com/valt-dev/valt/server/pkg/apierror"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := database.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer pool.Close()

	database.StartPartitionManager(ctx, pool)

	// Load JWT keys
	privPEM, err := os.ReadFile(cfg.JWTPrivateKeyPath)
	if err != nil {
		log.Fatalf("Failed to read JWT private key: %v", err)
	}
	pubPEM, err := os.ReadFile(cfg.JWTPublicKeyPath)
	if err != nil {
		log.Fatalf("Failed to read JWT public key: %v", err)
	}

	jwtMgr, err := auth.NewJWTManager(privPEM, pubPEM)
	if err != nil {
		log.Fatalf("Failed to init JWT manager: %v", err)
	}

	// Init MinIO storage
	storage, err := vault.NewMinIOStorage(
		cfg.MinioEndpoint, cfg.MinioAccessKey, cfg.MinioSecretKey,
		cfg.MinioBucket, cfg.MinioUseSSL,
	)
	if err != nil {
		log.Fatalf("Failed to init MinIO storage: %v", err)
	}

	// Decode master key for envelope encryption
	masterKey, err := cfg.MasterKey()
	if err != nil {
		log.Fatalf("Failed to load master key: %v", err)
	}

	// Init services
	auditLogger := audit.NewLogger(pool)
	emailSender := notify.NewEmailSender(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPassword, cfg.SMTPFrom)
	var emailNotifier notify.Notifier
	if emailSender != nil {
		emailNotifier = emailSender
	}
	tokenStore := notify.NewActionTokenStore(pool)
	channelStore := notify.NewChannelStore(pool)
	channelHandler := notify.NewChannelHandler(channelStore)
	slackAdapter := notify.NewSlackAdapter(cfg.SlackBotToken)
	telegramAdapter := notify.NewTelegramAdapter(cfg.TelegramBotToken)
	zaloAdapter := notify.NewZaloAdapter(cfg.ZaloOAToken, cfg.ZaloOAID)
	jobStore := notify.NewJobStore(pool)
	notifySvc := notify.NewService(emailNotifier, tokenStore, cfg.BaseURL, slackAdapter, telegramAdapter, channelStore, jobStore)

	// Start notification delivery worker (background goroutine)
	notifyWorker := notify.NewWorker(jobStore, emailNotifier, slackAdapter, telegramAdapter, zaloAdapter)
	go notifyWorker.Start(ctx)

	authHandler := auth.NewHandler(pool, jwtMgr, cfg)
	totpStore := auth.NewTOTPStore(pool, masterKey)
	totpHandler := auth.NewTOTPHandler(totpStore, jwtMgr)
	authHandler.SetTOTPHandler(totpHandler)
	// Wire email sender for transactional emails (verification, password reset).
	if emailSender != nil {
		authHandler.SetEmailSender(emailSender)
	}
	vaultService := vault.NewService(pool, storage)
	vaultHandler := vault.NewHandler(vaultService, masterKey)

	dynSvc := dynsecret.NewService(pool, masterKey)
	dynSvc.StartExpiryWorker(ctx)
	dynHandler := dynsecret.NewHandler(dynSvc, pool)

	workflowSvc := workflow.NewService(pool, cfg.PolicyEnforcementV2Enabled)
	credMgr := workflow.NewCredentialManager(pool, dynSvc)
	leaseIssuer := workflow.NewLeaseIssuer(credMgr, dynSvc, auditLogger)
	workflowHandler := workflow.NewHandler(workflowSvc, credMgr, leaseIssuer, vaultService, auditLogger, notifySvc, tokenStore, masterKey, pool)
	slackWebhookHandler := notify.NewSlackWebhookHandler(cfg.SlackSigningSecret, workflowHandler, slackAdapter)
	telegramWebhookHandler := notify.NewTelegramWebhookHandler(telegramAdapter, channelStore, pool, workflowHandler, cfg.TelegramBotUsername)

	// Auto-register Telegram webhook on startup (idempotent)
	if telegramAdapter != nil && cfg.BaseURL != "" {
		webhookURL := cfg.BaseURL + "/api/v1/webhooks/telegram"
		if err := telegramAdapter.SetWebhook(context.Background(), webhookURL); err != nil {
			log.Printf("Warning: failed to register Telegram webhook: %v", err)
		} else {
			log.Printf("Telegram webhook registered: %s", webhookURL)
		}
	}

	auditHandler := audit.NewHandler(pool)

	consentSvc := consent.NewService(pool)
	consentHandler := consent.NewHandler(consentSvc)

	orgSvc := org.NewService(pool)
	orgHandler := org.NewHandler(orgSvc)
	if emailSender != nil {
		orgHandler.SetEmailSender(emailSender, cfg.DashboardURL)
	}
	workspaceSvc := workspace.NewService(pool)
	workspaceHandler := workspace.NewHandler(workspaceSvc)
	projectSvc := project.NewService(pool)
	projectHandler := project.NewHandler(projectSvc)
	agentSvc := agent.NewService(pool)
	agentHandler := agent.NewHandler(agentSvc)
	policySvc := policy.NewService(pool)
	policyHandler := policy.NewHandler(policySvc)
	scannerSvc := scanner.NewService(pool)
	scannerHandler := scanner.NewHandler(scannerSvc, pool)

	// Redis rate limiter (optional — skip if REDIS_URL not set)
	var agentRateLimiter *ratelimit.RedisLimiter
	if cfg.RedisURL != "" {
		rl, err := ratelimit.NewRedisLimiter(cfg.RedisURL)
		if err != nil {
			log.Printf("Warning: Redis rate limiter init failed: %v", err)
		} else {
			agentRateLimiter = rl
			defer agentRateLimiter.Close()
		}
	}
	// agentRateLimiter is wired into the authenticated route group below

	// Billing (Stripe)
	var billingHandler *billing.Handler
	if cfg.StripeSecretKey != "" {
		billingSvc := billing.NewService(pool, cfg.StripeSecretKey, cfg.StripeWebhookSecret, cfg.StripePriceProID, cfg.StripePriceTeamID)
		billingHandler = billing.NewHandler(billingSvc, orgSvc)
	}

	// Integration store (Slack OAuth per-org)
	integrationStore := integration.NewStore(pool, masterKey)
	var slackOAuthHandler *integration.SlackOAuthHandler
	var integrationHandler *integration.IntegrationHandler
	if cfg.SlackClientID != "" {
		slackOAuthHandler = integration.NewSlackOAuthHandler(integrationStore, cfg.SlackClientID, cfg.SlackClientSecret, cfg.BaseURL+"/api/v1/oauth/slack/callback", cfg.DashboardURL, masterKey)
		integrationHandler = integration.NewIntegrationHandler(integrationStore)
	}

	// Webhooks (outbound HMAC-signed)
	webhookStore := webhooks.NewStore(pool)
	webhookHandler := webhooks.NewHandler(webhookStore)
	_ = webhooks.NewDispatcher(webhookStore) // dispatcher called from workflow handlers

	// Usage tracking
	usageTracker := usage.NewTracker(pool)
	usageHandler := usage.NewHandler(usageTracker)

	// Admin handler (super-admin dashboard endpoints)
	adminHandler := admin.NewHandler(pool)

	// Gateway proxy (optional)
	gatewayStore := gateway.NewStore(pool)
	gatewayHandler := gateway.NewHandler(gatewayStore)
	if cfg.GatewayEnabled {
		gw := gateway.NewServer(gatewayStore, agentSvc, vaultService, dynSvc, auditLogger, masterKey, cfg.GatewayPort)
		go func() {
			if err := gw.ListenAndServe(ctx); err != nil && err != http.ErrServerClosed {
				log.Printf("Gateway proxy failed: %v", err)
			}
		}()
	}

	// Rate limiters
	loginLimiter := custommiddleware.NewRateLimiter(5, 1*time.Minute)
	apiLimiter := custommiddleware.NewRateLimiter(100, 1*time.Minute)

	r := chi.NewRouter()

	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Timeout(30 * time.Second))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   strings.Split(cfg.CORSOrigins, ","),
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Get("/health", healthHandler(pool))

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(custommiddleware.SecurityHeaders)

		r.Route("/auth", func(r chi.Router) {
			// CLI polling endpoints — exempt from login rate limiter
			// CLI polls every 2s for up to 3 minutes (90 requests)
			r.Get("/cli-start", authHandler.CLIStart())
			r.Get("/cli-poll", authHandler.CLIPoll())

			// All other auth routes — strict rate limit (5/min per IP)
			r.Group(func(r chi.Router) {
				r.Use(loginLimiter.IPMiddleware())
				r.Mount("/", authHandler.Routes())
				r.Post("/accept-invite", orgHandler.AcceptInvitation)
			})
		})

		// Public: email action-token redemption (no JWT required)
		r.Post("/action-tokens/{token}/redeem", workflowHandler.RedeemActionToken)

		// Public: Slack interactivity callbacks (verified via HMAC-SHA256)
		r.Post("/webhooks/slack/interactions", slackWebhookHandler.Handle)

		// Public: Telegram Update callbacks (no auth — Telegram pushes to this endpoint)
		r.Post("/webhooks/telegram", telegramWebhookHandler.Handle)

		// Public: Stripe webhook (verified via signing secret)
		if billingHandler != nil {
			r.Post("/webhooks/stripe", billingHandler.HandleWebhook)
		}

		// Public: Slack OAuth callback (user redirected from Slack)
		if slackOAuthHandler != nil {
			r.Get("/oauth/slack/callback", slackOAuthHandler.Callback)
		}

		// Dual-auth routes: accept either user JWT or agent bearer token
		// These routes allow both users and AI agents to read/list data
		r.Group(func(r chi.Router) {
			r.Use(dualAuthMiddleware(jwtMgr, agentSvc))
			r.Use(apiLimiter.Middleware())
			if agentRateLimiter != nil {
				r.Use(agentRateLimiter.Middleware(60))
			}

			// GET secrets - readable by both users and agents
			r.Get("/secrets", vaultHandler.ListSecrets)
			r.Get("/secrets/{id}", vaultHandler.GetSecret)

			// Access request flow - readable by both
			r.Post("/secrets/{secret_id}/access-requests", workflowHandler.CreateRequest)
			r.Get("/access-requests/{request_id}", workflowHandler.GetRequest)
			r.Get("/credentials/active", workflowHandler.GetActiveCredentials)
			r.Get("/credentials/{request_id}", workflowHandler.GetCredential)
			r.Post("/credentials/{request_id}/revoke", workflowHandler.RevokeCredential)
		})

		// JWT-only authenticated routes: for write operations and user-specific operations
		r.Group(func(r chi.Router) {
			r.Use(auth.AuthMiddleware(jwtMgr))
			r.Use(apiLimiter.Middleware())
			if agentRateLimiter != nil {
				r.Use(agentRateLimiter.Middleware(60))
			}

			// TOTP 2FA management
			r.Post("/me/totp/setup", totpHandler.Setup)
			r.Post("/me/totp/verify", totpHandler.Verify)
			r.Delete("/me/totp", totpHandler.Disable)
			r.Post("/me/totp/backup-codes", totpHandler.RegenerateBackup)

			r.Get("/me/notification-channels", channelHandler.List)
			r.Post("/me/notification-channels", channelHandler.Upsert)
			r.Delete("/me/notification-channels/{id}", channelHandler.Delete)
			r.Post("/me/telegram-link", func(w http.ResponseWriter, r *http.Request) {
				userID := auth.UserIDFromContext(r.Context())
				url, err := telegramWebhookHandler.GenerateLinkURL(r.Context(), userID)
				if err != nil {
					apierror.InternalError(w, "failed to generate link")
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{"url": url})
			})

			// Secret write operations - JWT/users only
			r.Post("/secrets", vaultHandler.CreateSecret)
			r.Put("/secrets/{id}", vaultHandler.UpdateSecret)
			r.Delete("/secrets/{id}", vaultHandler.DeleteSecret)

			// Secret policy endpoints
			r.Get("/secrets/{id}/policy", vaultHandler.GetSecretPolicy)
			r.Put("/secrets/{id}/policy", vaultHandler.PutSecretPolicy)
			r.With(rbac.Middleware(pool, "project_id", rbac.ResourceProject, rbac.ActionAdmin)).
				Get("/projects/{project_id}/policy", projectHandler.GetProjectPolicy)
			r.With(rbac.Middleware(pool, "project_id", rbac.ResourceProject, rbac.ActionAdmin)).
				Put("/projects/{project_id}/policy", projectHandler.PutProjectPolicy)

			// Access request management - JWT/users only
			r.Get("/access-requests", workflowHandler.ListPending)
			r.Post("/access-requests/{request_id}/approve", workflowHandler.Approve)
			r.Post("/access-requests/{request_id}/reject", workflowHandler.Reject)

			// Audit and user-specific operations
			r.Mount("/audit", auditHandler.Routes())
			r.Mount("/consent", consentHandler.Routes())
			// Billing (checkout + portal)
			if billingHandler != nil {
				r.Post("/billing/checkout-session", billingHandler.CreateCheckout)
				r.Post("/billing/portal", billingHandler.CreatePortal)
			}
			// Integrations (Slack OAuth + list/disconnect)
			if slackOAuthHandler != nil {
				r.Get("/oauth/slack", slackOAuthHandler.Authorize)
				r.Get("/integrations", integrationHandler.List)
				r.Delete("/integrations/slack", integrationHandler.DeleteSlack)
			}
			r.Mount("/orgs", orgHandler.Routes())
			r.Post("/orgs/{org_id}/webhooks", webhookHandler.Create)
			r.Get("/orgs/{org_id}/webhooks", webhookHandler.List)
			r.Delete("/orgs/{org_id}/webhooks/{id}", webhookHandler.Delete)
			r.Mount("/orgs/{org_id}/workspaces", workspaceHandler.Routes())
			projectHandler.RegisterRoutes(r)
			agentHandler.RegisterRoutes(r)
			policyHandler.RegisterRoutes(r)
			gatewayHandler.RegisterRoutes(r)
			scannerHandler.RegisterRoutes(r)
			dynHandler.RegisterRoutes(r)
			usageHandler.RegisterRoutes(r)

			// Admin routes — restricted to users with role = 'admin'
			r.Route("/admin", func(r chi.Router) {
				r.Use(admin.AdminMiddleware(pool))
				r.Get("/stats", adminHandler.GetStats)
				r.Get("/users", adminHandler.ListUsers)
				r.Get("/orgs", adminHandler.ListOrgs)
				r.Get("/payments", adminHandler.ListPayments)
			})
		})
	})

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
	}

	go func() {
		log.Printf("Valt server starting on :%s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("Shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}
	log.Println("Server stopped")
}

func dualAuthMiddleware(jwtMgr *auth.JWTManager, agentSvc *agent.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				apierror.Unauthorized(w, "missing authorization header")
				return
			}
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				apierror.Unauthorized(w, "invalid authorization format")
				return
			}
			token := parts[1]

			// Try JWT first (no DB lookup)
			if userID, err := jwtMgr.ValidateAccessToken(token); err == nil {
				ctx := auth.WithUserID(r.Context(), userID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Fallback: try agent token
			if agentToken, err := agentSvc.ValidateToken(r.Context(), token); err == nil && agentToken != nil {
				ctx := agent.WithAgentID(r.Context(), agentToken.AgentID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			apierror.Unauthorized(w, "invalid or expired token")
		})
	}
}

type healthResponse struct {
	Status    string `json:"status"`
	Service   string `json:"service"`
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
	Database  string `json:"database"`
}

func healthHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dbStatus := "ok"
		if err := pool.Ping(r.Context()); err != nil {
			dbStatus = "unavailable"
		}

		status := "ok"
		statusCode := http.StatusOK
		if dbStatus != "ok" {
			status = "degraded"
			statusCode = http.StatusServiceUnavailable
		}

		resp := healthResponse{
			Status:    status,
			Service:   "valt-server",
			Version:   "0.1.0",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Database:  dbStatus,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("Failed to encode health response: %v", err)
		}
	}
}
