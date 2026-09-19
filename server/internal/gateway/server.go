package gateway

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/valt-dev/valt/server/internal/agent"
	"github.com/valt-dev/valt/server/internal/audit"
	"github.com/valt-dev/valt/server/internal/dynsecret"
	"github.com/valt-dev/valt/server/internal/vault"
	"github.com/valt-dev/valt/server/pkg/crypto"
)

// Server is the HTTP forward proxy that intercepts agent requests
// and injects real credentials in place of placeholder keys.
type Server struct {
	store     *Store
	agentSvc  *agent.Service
	vaultSvc  *vault.Service
	dynSvc    *dynsecret.Service
	auditLog  *audit.Logger
	masterKey []byte
	port      string
	client    *http.Client
}

// NewServer creates a new gateway proxy Server. dynSvc may be nil, which
// disables derived-API-key authentication (all other behavior is unchanged).
func NewServer(store *Store, agentSvc *agent.Service, vaultSvc *vault.Service, dynSvc *dynsecret.Service, auditLog *audit.Logger, masterKey []byte, port string) *Server {
	return &Server{
		store:     store,
		agentSvc:  agentSvc,
		vaultSvc:  vaultSvc,
		dynSvc:    dynSvc,
		auditLog:  auditLog,
		masterKey: masterKey,
		port:      port,
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // don't follow redirects
			},
		},
	}
}

// ListenAndServe starts the proxy gateway on the configured port.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:    ":" + s.port,
		Handler: s,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx) //nolint:errcheck
	}()

	log.Printf("Gateway proxy starting on :%s", s.port)
	return srv.ListenAndServe()
}

// ServeHTTP dispatches proxy requests (HTTP CONNECT or regular HTTP).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handleHTTP(w, r)
}

// handleHTTP processes regular HTTP requests through the proxy.
// This is the main credential injection path.
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Authenticate: agent token (Proxy-Authorization) and/or a derived
	// API key (Authorization, valt_dk_ prefix). A valid derived key on its
	// own also authenticates — the lease carries the entitlement.
	agentID, lease, authErr := s.authenticateRequest(r)
	if authErr != nil {
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		return
	}

	targetHost := r.URL.Host
	targetPath := r.URL.Path
	if targetHost == "" {
		targetHost = r.Host
	}

	// Block SSRF: reject requests to private/internal IPs
	if isPrivateHost(targetHost) {
		http.Error(w, "Forbidden: private network access blocked", http.StatusForbidden)
		return
	}

	// Strip port for pattern matching
	host := stripPort(targetHost)

	// 2. Check endpoint rate limit / block
	limit, err := s.store.FindEndpointLimit(r.Context(), agentID, host, targetPath)
	if err != nil {
		log.Printf("gateway: endpoint limit check error: %v", err)
	}
	if limit != nil && limit.Blocked {
		http.Error(w, "Forbidden: endpoint blocked for this agent", http.StatusForbidden)
		return
	}

	// 3. Find matching route — try placeholder scan first, then host+path.
	// Skipped when a derived key authenticated the request: that lease
	// already determines the credential, which is the provider's master key.
	var route *ProxyRoute
	placeholder := ""
	if lease == nil {
		placeholder = ScanForPlaceholder(r)
		if placeholder != "" {
			route, err = s.store.FindByPlaceholder(r.Context(), placeholder)
			if err != nil {
				log.Printf("gateway: placeholder lookup error: %v", err)
			}
			// Verify the route belongs to this agent
			if route != nil && route.AgentID != agentID {
				route = nil
			}
		}
		if route == nil {
			route, err = s.store.FindMatchingRoute(r.Context(), agentID, host, targetPath)
			if err != nil {
				log.Printf("gateway: route match error: %v", err)
			}
		}
	}

	// 4. Inject credential: derived-key lease → the provider's master key;
	// otherwise the route's secret value.
	if lease != nil {
		if injectErr := s.injectLeaseMasterKey(r, lease); injectErr != nil {
			log.Printf("gateway: master key injection error for lease %s: %v", lease.ID, injectErr)
			http.Error(w, "internal proxy error", http.StatusBadGateway)
			return
		}
	} else if route != nil {
		secretValue, decryptErr := s.decryptSecret(r.Context(), route.SecretID)
		if decryptErr != nil {
			log.Printf("gateway: decrypt error for secret %s: %v", route.SecretID, decryptErr)
			http.Error(w, "internal proxy error", http.StatusBadGateway)
			return
		}
		// Strip placeholder before injecting real value
		if placeholder != "" {
			StripPlaceholder(r, placeholder)
		}
		InjectCredential(r, route, secretValue)
	}

	// 5. Strip proxy headers before forwarding
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Proxy-Connection")

	// 6. Build outbound request — upgrade to HTTPS
	outURL := *r.URL
	if outURL.Scheme == "" || outURL.Scheme == "http" {
		outURL.Scheme = "https"
	}
	if outURL.Host == "" {
		outURL.Host = targetHost
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	outReq.Header = r.Header.Clone()
	outReq.ContentLength = r.ContentLength

	// 7. Forward
	resp, err := s.client.Do(outReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 8. Copy response back
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck

	// 9. Audit log (fire and forget)
	routeID := ""
	if route != nil {
		routeID = route.ID
	}
	go s.logProxyRequest(context.Background(), agentID, audit.ExtractIP(r), r.UserAgent(), host, targetPath, routeID)
}

// handleConnect handles HTTPS CONNECT tunnel (no credential injection possible).
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	agentID, _, err := s.authenticateRequest(r)
	if err != nil {
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		return
	}

	// Block SSRF: reject connections to private/internal IPs
	if isPrivateHost(r.Host) {
		http.Error(w, "Forbidden: private network access blocked", http.StatusForbidden)
		return
	}

	// Check endpoint block
	host := stripPort(r.Host)
	limit, _ := s.store.FindEndpointLimit(r.Context(), agentID, host, "/*")
	if limit != nil && limit.Blocked {
		http.Error(w, "Forbidden: endpoint blocked", http.StatusForbidden)
		return
	}

	// Establish TCP tunnel
	targetConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		targetConn.Close()
		return
	}

	w.WriteHeader(http.StatusOK)
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		targetConn.Close()
		return
	}

	// Bidirectional copy
	go transfer(targetConn, clientConn)
	go transfer(clientConn, targetConn)

	go s.logProxyRequest(context.Background(), agentID, audit.ExtractIP(r), r.UserAgent(), host, "CONNECT", "")
}

// authenticateRequest authenticates a proxied request and returns the agent
// identity plus, when the request presented a Valt-derived API key, its lease.
//
// Accepted credentials (in order):
//  1. Agent token in Proxy-Authorization, optionally combined with a derived
//     key in Authorization — agent identity + lease entitlement, bound together.
//  2. A derived key alone in Proxy-Authorization — the lease is the
//     entitlement; its agent_id (if any) becomes the identity.
func (s *Server) authenticateRequest(r *http.Request) (string, *dynsecret.LeaseInfo, error) {
	agentID, tokenErr := s.validateAgentToken(r)
	if tokenErr == nil {
		if key := derivedKeyFromAuthorization(r); key != "" {
			if s.dynSvc == nil {
				return "", nil, fmt.Errorf("derived API keys are not enabled")
			}
			lease, err := derivedKeyAuth(r.Context(), s.dynSvc, key, agentID)
			if err != nil {
				logDerivedKeyError(agentID, err)
				return "", nil, err
			}
			return agentID, lease, nil
		}
		return agentID, nil, nil
	}

	if key := bearerTokenFrom(r.Header.Get("Proxy-Authorization")); strings.HasPrefix(key, dynsecret.DerivedKeyPrefix) {
		if s.dynSvc == nil {
			return "", nil, fmt.Errorf("derived API keys are not enabled")
		}
		lease, err := derivedKeyAuth(r.Context(), s.dynSvc, key, "")
		if err != nil {
			logDerivedKeyError("", err)
			return "", nil, err
		}
		id := ""
		if lease.AgentID != nil {
			id = *lease.AgentID
		}
		return id, lease, nil
	}

	return "", nil, tokenErr
}

// validateAgentToken validates the Proxy-Authorization bearer agent token
// and returns the agent identity.
func (s *Server) validateAgentToken(r *http.Request) (string, error) {
	header := r.Header.Get("Proxy-Authorization")
	if header == "" {
		return "", fmt.Errorf("missing Proxy-Authorization")
	}
	token := bearerTokenFrom(header)
	if token == "" {
		return "", fmt.Errorf("invalid Proxy-Authorization format")
	}
	ident, err := s.agentSvc.ValidateToken(r.Context(), token)
	if err != nil || ident == nil {
		return "", fmt.Errorf("invalid agent token")
	}
	return ident.AgentID, nil
}

// bearerTokenFrom extracts the token from a "Bearer <token>" header value.
func bearerTokenFrom(header string) string {
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// derivedKeyFromAuthorization returns the derived API key from the
// Authorization header if one is present, otherwise "".
func derivedKeyFromAuthorization(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		header = strings.TrimPrefix(header, "Bearer ")
	}
	header = strings.TrimSpace(header)
	if strings.HasPrefix(header, dynsecret.DerivedKeyPrefix) {
		return header
	}
	return ""
}

// injectLeaseMasterKey replaces the presented derived API key with the
// provider's real master key, per the provider's injection config
// (injection_type/injection_key, default bearer on Authorization).
func (s *Server) injectLeaseMasterKey(r *http.Request, lease *dynsecret.LeaseInfo) error {
	pc, err := s.dynSvc.GetProvider(r.Context(), lease.ProviderID)
	if err != nil {
		return fmt.Errorf("provider not found: %w", err)
	}
	masterKey := pc.Config["master_key"]
	if masterKey == "" {
		return fmt.Errorf("provider %s has no master_key configured", pc.ID)
	}

	route := &ProxyRoute{
		InjectionType:   pc.Config["injection_type"],
		InjectionKey:    pc.Config["injection_key"],
		InjectionFormat: "{value}",
	}
	if route.InjectionKey == "" {
		route.InjectionType = "bearer"
	}

	// The derived key never reaches the upstream API.
	for _, h := range []string{"Authorization", "Proxy-Authorization"} {
		if v := r.Header.Get(h); v != "" && strings.Contains(v, dynsecret.DerivedKeyPrefix) {
			r.Header.Del(h)
		}
	}
	InjectCredential(r, route, masterKey)
	return nil
}

// decryptSecret retrieves and decrypts a secret value for credential injection.
func (s *Server) decryptSecret(ctx context.Context, secretID string) (string, error) {
	secret, err := s.vaultSvc.GetSecretByID(ctx, secretID)
	if err != nil || secret == nil {
		return "", fmt.Errorf("secret not found: %s", secretID)
	}

	// Unwrap DEK with master key
	dek, err := crypto.DecryptAES256GCM(s.masterKey, secret.EncryptedDEK)
	if err != nil {
		return "", fmt.Errorf("unwrapping DEK: %w", err)
	}

	// Fetch encrypted blob from MinIO
	blob, err := s.vaultSvc.GetBlob(ctx, secret.StorageKey)
	if err != nil {
		return "", fmt.Errorf("fetching blob: %w", err)
	}

	// Decrypt blob with DEK
	plaintext, err := crypto.DecryptAES256GCM(dek, blob)
	if err != nil {
		return "", fmt.Errorf("decrypting blob: %w", err)
	}

	return string(plaintext), nil
}

// logProxyRequest writes an audit entry for a proxied request. clientIP and
// userAgent are captured from the inbound agent request before the goroutine
// fires so the audit entry carries the full where-context.
func (s *Server) logProxyRequest(ctx context.Context, agentID, clientIP, userAgent, host, path, routeID string) {
	metadata := fmt.Sprintf(`{"host":"%s","path":"%s","route_id":"%s"}`, host, path, routeID)
	if _, err := s.auditLog.Log(ctx, audit.Entry{
		UserID:       agentID,
		Action:       "proxy_request",
		ResourceType: "gateway",
		ResourceID:   routeID,
		EventType:    "action",
		Status:       "success",
		IPAddress:    clientIP,
		UserAgent:    userAgent,
		Metadata:     metadata,
	}); err != nil {
		log.Printf("gateway: audit log error: %v", err)
	}
}

func stripPort(host string) string {
	if i := strings.LastIndex(host, ":"); i >= 0 {
		return host[:i]
	}
	return host
}

// privateIPNets contains RFC 1918, loopback, link-local, and cloud metadata ranges.
var privateIPNets = func() []*net.IPNet {
	cidrs := []string{
		"127.0.0.0/8",    // loopback
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"169.254.0.0/16", // link-local / cloud metadata
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 unique local
		"fe80::/10",      // IPv6 link-local
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, n, _ := net.ParseCIDR(cidr)
		nets = append(nets, n)
	}
	return nets
}()

// isPrivateHost resolves a hostname and returns true if any resolved IP is private.
// Blocks SSRF attacks targeting internal services, cloud metadata (169.254.169.254), etc.
func isPrivateHost(host string) bool {
	h := stripPort(host)
	// Direct IP check
	if ip := net.ParseIP(h); ip != nil {
		for _, n := range privateIPNets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	// DNS resolution check
	addrs, err := net.LookupHost(h)
	if err != nil {
		return false // can't resolve — let the dial fail naturally
	}
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil {
			for _, n := range privateIPNets {
				if n.Contains(ip) {
					return true
				}
			}
		}
	}
	return false
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src) //nolint:errcheck
}
