package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/chaudharydeepak/prompt-guard/inspector"
	"github.com/chaudharydeepak/prompt-guard/proxy"
	"github.com/chaudharydeepak/prompt-guard/store"
	"github.com/chaudharydeepak/prompt-guard/web"
)

func main() {
	port          := flag.Int("port", 8080, "Proxy port")
	webPort       := flag.Int("web-port", 7778, "Web dashboard port")
	caDir         := flag.String("ca-dir", defaultCADir(), "Directory for CA cert/key and database")
	upstreamProxy := flag.String("upstream-proxy", "", "Corporate proxy to route outbound traffic through (e.g. http://proxy.corp.com:8080)")
	debug         := flag.Bool("debug", false, "Enable verbose request/connection logging")
	flag.Parse()

	proxy.Debug = *debug

	if err := os.MkdirAll(*caDir, 0700); err != nil {
		log.Fatalf("mkdir %s: %v", *caDir, err)
	}

	db, err := store.Open(filepath.Join(*caDir, "prompt-guard.db"))
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

	printSetup(ca.CertPath, *port, *webPort, *upstreamProxy)
	web.Start(*webPort, db, eng, filepath.Join(*caDir, "rules.json"))
	log.Fatal(proxy.Start(*port, ca, db, eng, *upstreamProxy))
}

func defaultCADir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".prompt-guard")
}

func printSetup(certPath string, port, webPort int, upstreamProxy string) {
	fmt.Println("\n┌─────────────────────────────────────────┐")
	fmt.Println("│           Prompt Guard starting         │")
	fmt.Println("└─────────────────────────────────────────┘")
	fmt.Printf("\nCA cert:   %s\n\n", certPath)

	switch runtime.GOOS {
	case "darwin":
		fmt.Printf("Install CA (run once):\n  sudo security add-trusted-cert -d -r trustRoot \\\n    -k /Library/Keychains/System.keychain %s\n\n", certPath)
	case "linux":
		fmt.Printf("Install CA (run once):\n  sudo cp %s /usr/local/share/ca-certificates/prompt-guard.crt\n  sudo update-ca-certificates\n\n", certPath)
	case "windows":
		fmt.Printf("Install CA (run once):\n  certutil -addstore -f ROOT %s\n\n", certPath)
	}

	fmt.Printf("Set proxy:\n  export HTTP_PROXY=http://localhost:%d\n  export HTTPS_PROXY=http://localhost:%d\n  export NO_PROXY=localhost,127.0.0.1\n\n", port, port)
	fmt.Printf("Dashboard:  http://localhost:%d\n", webPort)
	fmt.Printf("Rules file: %s\n", filepath.Join(filepath.Dir(certPath), "rules.json"))
	if upstreamProxy != "" {
		fmt.Printf("Upstream:   %s\n", upstreamProxy)
	}
	fmt.Println()
}
