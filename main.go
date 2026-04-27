package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/chaudharydeepak/redasq/inspector"
	"github.com/chaudharydeepak/redasq/mlclient"
	"github.com/chaudharydeepak/redasq/mlspawn"
	"github.com/chaudharydeepak/redasq/proxy"
	"github.com/chaudharydeepak/redasq/store"
	"github.com/chaudharydeepak/redasq/web"
)

// version is set at build time via -ldflags="-X main.version=v1.2.3"
var version = "dev"

func main() {
	showVersion   := flag.Bool("version", false, "Print version and exit")
	port          := flag.Int("port", 8080, "Proxy port")
	webPort       := flag.Int("web-port", 7778, "Web dashboard port")
	caDir         := flag.String("ca-dir", defaultCADir(), "Directory for CA cert/key and database")
	upstreamProxy := flag.String("upstream-proxy", "", "Corporate proxy to route outbound traffic through (e.g. http://proxy.corp.com:8080)")
	mlURL         := flag.String("ml-url", os.Getenv("REDASQ_ML_URL"), "External classifier URL; empty means redasq spawns its own sidecar")
	mlPort        := flag.Int("ml-port", 18001, "Port for the auto-spawned classifier sidecar")
	mlVenv        := flag.String("ml-venv", os.Getenv("REDASQ_VENV"), "Python venv for the auto-spawned sidecar (default eval/.venv)")
	noML          := flag.Bool("no-ml", false, "Disable the classifier entirely")
	debug         := flag.Bool("debug", false, "Enable verbose request/connection logging")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	proxy.Debug = *debug

	if err := os.MkdirAll(*caDir, 0700); err != nil {
		log.Fatalf("mkdir %s: %v", *caDir, err)
	}

	db, err := store.Open(filepath.Join(*caDir, "redasq.db"))
	if err != nil {
		log.Fatalf("store: %v", err)
	}

	ca, err := proxy.LoadOrCreateCA(*caDir)
	if err != nil {
		log.Fatalf("ca: %v", err)
	}

	eng := inspector.New()

	// Load rules.json config (custom rules + overrides). Missing file is fine.
	cfg, err := inspector.LoadConfig(filepath.Join(*caDir, "rules.json"))
	if err != nil {
		log.Fatalf("rules.json: %v", err)
	}
	for _, o := range cfg.Overrides {
		if o.Mode != "" {
			eng.SetMode(o.ID, inspector.Mode(o.Mode))
		}
		if o.Severity != "" {
			eng.SetSeverity(o.ID, inspector.Severity(o.Severity))
		}
	}
	for _, rc := range cfg.Rules {
		pat := regexp.MustCompile(rc.Pattern)
		eng.AddRule(inspector.Rule{
			ID:          rc.ID,
			Name:        rc.Name,
			Description: rc.Description,
			Pattern:     pat,
			Severity:    inspector.Severity(rc.Severity),
			Mode:        inspector.Mode(rc.Mode),
			Replacement: "[REDACTED]",
		})
	}

	if db.GetSetting("agent_mode", "false") == "true" {
		eng.SetAgentMode(true)
		log.Printf("agent mode: ON (persisted from last run)")
	}

	mlClient, sidecar, mlStatus := setupML(*noML, *mlURL, *mlPort, *mlVenv)

	// Sidecar is owned by this process — kill it if redasq is stopped.
	if sidecar != nil {
		go func() {
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
			<-sigCh
			fmt.Fprintln(os.Stderr, "\n→ stopping classifier sidecar")
			sidecar.Stop()
			os.Exit(0)
		}()
	}

	web.Version = version
	printSetup(ca.CertPath, *port, *webPort, *upstreamProxy, mlStatus)

	// Adapter so the web package can call mlClient without importing it
	// (avoids dragging the http client into the test binary).
	var mlAdapter web.MLClassifier
	if mlClient != nil {
		c := mlClient
		mlAdapter = &web.MLAdapter{
			URLValue: c.URL(),
			ClassifyFn: func(ctx context.Context, text string) (any, error) {
				return c.Classify(ctx, text)
			},
		}
	}
	web.Start(*webPort, db, eng, filepath.Join(*caDir, "rules.json"), mlAdapter)
	err = proxy.Start(*port, ca, db, eng, mlClient, *upstreamProxy)
	if sidecar != nil {
		sidecar.Stop()
	}
	log.Fatal(err)
}

// setupML resolves the ML configuration and either returns an external
// client, spawns a local sidecar, or disables ML with a clear status string.
// status is a single line for the startup banner.
func setupML(disabled bool, externalURL string, port int, venv string) (*mlclient.Client, *mlspawn.Sidecar, string) {
	if disabled {
		return nil, nil, "disabled (--no-ml)"
	}
	if externalURL != "" {
		model := fetchModelName(externalURL)
		return mlclient.New(externalURL, 3*time.Second), nil, fmtMLStatus(externalURL, model, "external")
	}

	repoRoot := repoRootDir()
	logPath := filepath.Join(os.TempDir(), "redasq-ml.log")

	fmt.Fprintf(os.Stderr, "→ loading classifier model (one-time, ~10s)... ")
	side, err := mlspawn.Start(repoRoot, venv, port, logPath, 60*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "skipped")
		if errors.Is(err, mlspawn.ErrNoVenv) {
			hint := mlspawn.VenvSetupHint(venv)
			return nil, nil, "disabled (no venv) — set up with: " + hint
		}
		log.Printf("ml: sidecar failed to start: %v", err)
		return nil, nil, "disabled (sidecar failed — see " + logPath + ")"
	}
	model := fetchModelName(side.URL)
	fmt.Fprintf(os.Stderr, "✓ ready (pid %d, model=%s)\n", side.PID(), modelOrDash(model))
	return mlclient.New(side.URL, 3*time.Second), side, fmtMLStatus(side.URL, model, "managed")
}

// fetchModelName queries the sidecar's /health endpoint and returns the
// "model" field. Empty on any error — callers display "—" then.
func fetchModelName(classifyURL string) string {
	u, err := url.Parse(classifyURL)
	if err != nil {
		return ""
	}
	healthURL := strings.TrimSuffix(u.String(), u.Path) + "/health"
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(healthURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var body struct {
		Status string `json:"status"`
		Model  string `json:"model"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return ""
	}
	return body.Model
}

func fmtMLStatus(url, model, mode string) string {
	if model == "" {
		return fmt.Sprintf("%s  ✓ ready (%s)", url, mode)
	}
	return fmt.Sprintf("%s  ✓ ready (%s, model=%s)", url, mode, model)
}

func modelOrDash(model string) string {
	if model == "" {
		return "—"
	}
	return model
}

// repoRootDir returns the directory the binary was launched from, falling
// back to the directory containing the executable. The Python sidecar is
// spawned with this as its working directory so it can find ml/.
func repoRootDir() string {
	if cwd, err := os.Getwd(); err == nil {
		if _, err := os.Stat(filepath.Join(cwd, "ml", "classifier_server.py")); err == nil {
			return cwd
		}
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		if _, err := os.Stat(filepath.Join(dir, "ml", "classifier_server.py")); err == nil {
			return dir
		}
	}
	cwd, _ := os.Getwd()
	return cwd
}

func defaultCADir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".redasq")
}

func printSetup(certPath string, port, webPort int, upstreamProxy, mlStatus string) {
	fmt.Println("\n┌─────────────────────────────────────────┐")
	fmt.Printf( "│        Redasq %-20s│\n", version)
	fmt.Println("└─────────────────────────────────────────┘")
	fmt.Printf("\nCA cert:   %s\n\n", certPath)

	fmt.Printf("Install CA (optional — only needed for browser inspection):\n")
	switch runtime.GOOS {
	case "darwin":
		fmt.Printf("  sudo security add-trusted-cert -d -r trustRoot \\\n    -k /Library/Keychains/System.keychain %s\n\n", certPath)
	case "linux":
		fmt.Printf("  sudo cp %s /usr/local/share/ca-certificates/redasq.crt\n  sudo update-ca-certificates\n\n", certPath)
	case "windows":
		fmt.Printf("  certutil -addstore -f ROOT %s\n\n", certPath)
	}

	switch runtime.GOOS {
	case "windows":
		fmt.Printf("Set proxy (PowerShell):\n  $env:HTTP_PROXY=\"http://localhost:%d\"\n  $env:HTTPS_PROXY=\"http://localhost:%d\"\n  $env:NO_PROXY=\"localhost,127.0.0.1\"\n  $env:NODE_EXTRA_CA_CERTS=\"%s\"\n\n", port, port, certPath)
		fmt.Printf("Set proxy (Command Prompt):\n  set HTTP_PROXY=http://localhost:%d\n  set HTTPS_PROXY=http://localhost:%d\n  set NO_PROXY=localhost,127.0.0.1\n  set NODE_EXTRA_CA_CERTS=%s\n\n", port, port, certPath)
	default:
		fmt.Printf("Set proxy:\n  export HTTP_PROXY=http://localhost:%d\n  export HTTPS_PROXY=http://localhost:%d\n  export NO_PROXY=localhost,127.0.0.1\n\n", port, port)
	}
	fmt.Printf("Dashboard:  http://localhost:%d\n", webPort)
	fmt.Printf("Rules file: %s\n", filepath.Join(filepath.Dir(certPath), "rules.json"))
	if upstreamProxy != "" {
		fmt.Printf("Upstream:   %s\n", upstreamProxy)
	}
	fmt.Printf("ML:         %s\n", mlStatus)
	fmt.Println()
}
