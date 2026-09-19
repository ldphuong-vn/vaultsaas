package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	neturl "net/url"

	"github.com/spf13/cobra"
	"github.com/valt-dev/valt/valt-cli/internal/api"
	"github.com/valt-dev/valt/valt-cli/internal/config"
	"github.com/valt-dev/valt/valt-cli/internal/keychain"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Interactive setup wizard — configure API URL, login, pick project",
	RunE:  runSetup,
}

func init() { rootCmd.AddCommand(setupCmd) }

func runSetup(cmd *cobra.Command, args []string) error {
	reader := bufio.NewReader(os.Stdin)

	// Step 1: API URL
	fmt.Print("Valt API URL [https://api.valt.dev]: ")
	apiURL, _ := reader.ReadString('\n')
	apiURL = strings.TrimSpace(apiURL)
	if apiURL == "" {
		apiURL = "https://api.valt.dev"
	}

	client := api.New(apiURL, "")

	// Step 2: Start CLI session
	var session struct {
		SessionID string `json:"session_id"`
		LoginURL  string `json:"login_url"`
	}
	if err := client.Get(context.Background(), "/auth/cli-start", &session); err != nil {
		return fmt.Errorf("failed to start login session: %w", err)
	}

	fmt.Println("\nOpening browser for login...")
	openBrowser(session.LoginURL)
	fmt.Println("Login URL:", session.LoginURL)
	fmt.Println("Waiting for login...")

	// Step 3: Poll for token
	token, err := pollForToken(client, session.SessionID)
	if err != nil {
		return err
	}

	if err := keychain.SetToken(token); err != nil {
		return fmt.Errorf("storing token: %w", err)
	}
	fmt.Println("✓ Logged in")

	// Step 4: Pick project
	authedClient := api.New(apiURL, token)
	var orgsResp struct {
		Orgs []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"orgs"`
	}
	if err := authedClient.Get(context.Background(), "/orgs", &orgsResp); err != nil {
		return fmt.Errorf("fetching orgs: %w", err)
	}
	if len(orgsResp.Orgs) == 0 {
		fmt.Println("No orgs found. Create one in the dashboard first.")
		return nil
	}
	fmt.Println("\nOrganizations:")
	for i, o := range orgsResp.Orgs {
		fmt.Printf("  %d. %s\n", i+1, o.Name)
	}
	fmt.Print("Pick org [1]: ")
	orgChoice, _ := reader.ReadString('\n')
	orgIdx := parseChoice(strings.TrimSpace(orgChoice), 1) - 1
	if orgIdx < 0 || orgIdx >= len(orgsResp.Orgs) {
		orgIdx = 0
	}
	orgID := orgsResp.Orgs[orgIdx].ID

	// Fetch projects (simplified — first workspace)
	var wsResp struct {
		Workspaces []struct {
			ID string `json:"id"`
		} `json:"workspaces"`
	}
	authedClient.Get(context.Background(), "/orgs/"+orgID+"/workspaces", &wsResp) //nolint:errcheck
	var projectID string
	if len(wsResp.Workspaces) > 0 {
		var projResp struct {
			Projects []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"projects"`
		}
		authedClient.Get(context.Background(), "/workspaces/"+wsResp.Workspaces[0].ID+"/projects", &projResp) //nolint:errcheck
		if len(projResp.Projects) > 0 {
			fmt.Println("\nProjects:")
			for i, p := range projResp.Projects {
				fmt.Printf("  %d. %s\n", i+1, p.Name)
			}
			fmt.Print("Pick project [1]: ")
			projChoice, _ := reader.ReadString('\n')
			projIdx := parseChoice(strings.TrimSpace(projChoice), 1) - 1
			if projIdx < 0 || projIdx >= len(projResp.Projects) {
				projIdx = 0
			}
			projectID = projResp.Projects[projIdx].ID
		}
	}

	// Save config
	cfg := &config.Config{APIURL: apiURL, ProjectID: projectID}
	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	fmt.Println("\n✓ Setup complete!")
	fmt.Println("Next: valt mcp install --ide claude")
	return nil
}

func pollForToken(client *api.Client, sessionID string) (string, error) {
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		var result struct {
			Status string `json:"status"`
			Token  string `json:"token"`
		}
		if err := client.Get(context.Background(), "/auth/cli-poll?session="+sessionID, &result); err != nil {
			return "", err
		}
		if result.Status == "complete" && result.Token != "" {
			return result.Token, nil
		}
		time.Sleep(2 * time.Second)
	}
	return "", fmt.Errorf("login timed out after 3 minutes")
}

func openBrowser(rawURL string) {
	// Only http(s) targets are ever opened; anything else is a caller bug.
	u, err := neturl.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return
	}
	target := u.String()
	switch runtime.GOOS {
	case "windows":
		// "start" is a cmd builtin; rundll32 keeps the URL a single argv
		// entry without involving a shell.
		exec.Command("rundll32", "url.dll,FileProtocolHandler", target).Start() //nolint:errcheck
	case "darwin":
		exec.Command("open", target).Start() //nolint:errcheck
	default:
		exec.Command("xdg-open", target).Start() //nolint:errcheck
	}
}

func parseChoice(s string, def int) int {
	n := def
	fmt.Sscan(s, &n) //nolint:errcheck
	return n
}
