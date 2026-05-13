package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"syscall"
	"time"

	"github.com/chaudharydeepak/redasq/inspector"
	"github.com/chaudharydeepak/redasq/mlclassifier"
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
	debug         := flag.Bool("debug", false, "Enable verbose request/connection logging")
	noML          := flag.Bool("no-ml-classifier", false, "Disable the parallel local-LLM classifier")
	mlBinary      := flag.String("ml-binary", mlclassifier.DefaultBinary, "Path to llama-server binary (looked up in PATH if not absolute)")
	mlModel       := flag.String("ml-model", "", "Path to GGUF model file (default: <ca-dir>/models/"+mlclassifier.DefaultModelFile+")")
	mlPort        := flag.Int("ml-port", mlclassifier.DefaultPort, "Port for the managed llama-server")
	mlThreads     := flag.Int("ml-threads", 8, "Number of threads for llama-server")
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

	// Try to bring up the local-LLM classifier. Failures here are non-fatal —
	// redasq continues with regex-only behavior and the dashboard shows empty
	// ml_classification values for new rows.
	mlClient, mlServer := startMLClassifier(*noML, *mlBinary, *mlModel, *mlPort, *mlThreads, *caDir)

	// Clean shutdown so the spawned llama-server doesn't outlive redasq.
	// Without this the child gets reparented to launchd / init when redasq
	// dies and keeps the port + ~2.5 GB resident memory.
	if mlServer != nil {
		go shutdownOnSignal(mlServer)
	}

	web.Version = version
	printSetup(ca.CertPath, *port, *webPort, *upstreamProxy)
	web.Start(*webPort, db, eng, filepath.Join(*caDir, "rules.json"))
	log.Fatal(proxy.Start(*port, ca, db, eng, *upstreamProxy, mlClient))
}

// startMLClassifier spawns llama-server unless --no-ml-classifier is set.
// Missing binary or model logs a hint and returns (nil, nil) so redasq runs
// in regex-only mode.
func startMLClassifier(disabled bool, binary, model string, port, threads int, caDir string) (*mlclassifier.Client, *mlclassifier.Spawned) {
	if disabled {
		log.Printf("ml: disabled (--no-ml-classifier)")
		return nil, nil
	}
	if model == "" {
		model = filepath.Join(caDir, "models", mlclassifier.DefaultModelFile)
	}
	cfg := mlclassifier.Config{
		Binary:  binary,
		Model:   model,
		Port:    port,
		Threads: threads,
	}
	log.Printf("ml: spawning %s with %s ...", filepath.Base(binary), filepath.Base(model))
	spawned, err := mlclassifier.Spawn(context.Background(), cfg, 60*time.Second)
	if err != nil {
		log.Printf("ml: disabled — %v", err)
		log.Printf("ml: to enable, install llama.cpp (brew install llama.cpp) and place a GGUF at %s", model)
		return nil, nil
	}
	log.Printf("ml: ready at %s (model=%s, logs=%s)", spawned.URL, spawned.Model, spawned.LogPath)
	return mlclassifier.New(spawned.URL), spawned
}

func shutdownOnSignal(spawned *mlclassifier.Spawned) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	log.Printf("ml: stopping llama-server ...")
	_ = spawned.Stop()
	os.Exit(0)
}

func defaultCADir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".redasq")
}

func printSetup(certPath string, port, webPort int, upstreamProxy string) {
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
	fmt.Println()
}
