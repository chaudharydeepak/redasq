package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/chaudharydeepak/prompt-guard/inspector"
	"github.com/chaudharydeepak/prompt-guard/store"
)

// targetSuffixes are hostname suffixes we intercept.
var targetSuffixes = []string{
	"api.openai.com",
	"api.anthropic.com",
	"api.githubcopilot.com",
	"copilot-proxy.githubusercontent.com",
	".githubcopilot.com",
	".openai.com",
	".anthropic.com",
}

func isTarget(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	for _, suffix := range targetSuffixes {
		if host == suffix || strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

type proxy struct {
	ca  *CA
	db  *store.Store
	eng *inspector.Engine
}

// Start runs the HTTP proxy on the given port. Blocks until error.
func Start(port int, ca *CA, db *store.Store, eng *inspector.Engine) error {
	p := &proxy{ca: ca, db: db, eng: eng}
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: p,
	}
	log.Printf("proxy: listening on :%d", port)
	return srv.ListenAndServe()
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleCONNECT(w, r)
		return
	}
	p.handlePlainHTTP(w, r)
}

// handleCONNECT handles HTTPS CONNECT tunnels.
func (p *proxy) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}

	// Acknowledge the CONNECT
	fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection established\r\n\r\n")

	if isTarget(r.Host) {
		p.mitm(clientConn, r.Host)
	} else {
		tunnel(clientConn, r.Host)
	}
}

// mitm performs TLS man-in-the-middle interception.
func (p *proxy) mitm(clientConn net.Conn, hostport string) {
	defer clientConn.Close()

	hostname := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		hostname = h
	}

	cert, err := p.ca.IssueCert(hostname)
	if err != nil {
		log.Printf("mitm: cert error %s: %v", hostname, err)
		return
	}

	tlsClient := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err := tlsClient.Handshake(); err != nil {
		// Likely: client doesn't trust our CA yet
		log.Printf("mitm: TLS handshake failed for %s — is the CA cert trusted? (%v)", hostname, err)
		return
	}
	defer tlsClient.Close()

	br := bufio.NewReader(tlsClient)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		req.URL.Scheme = "https"
		req.URL.Host = hostport

		// Buffer the request body so we can inspect it then re-send it.
		var body []byte
		if req.Body != nil {
			body, _ = io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(body))
		}

		// Inspect before forwarding
		p.inspectAndStore(req, hostport, body)

		// Forward to real upstream and pipe response back
		if err := p.forward(tlsClient, req, hostport); err != nil {
			return
		}
	}
}

// forward dials the real upstream, sends the request, and writes the response back to dst.
func (p *proxy) forward(dst net.Conn, req *http.Request, hostport string) error {
	hostname := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		hostname = h
	}

	up, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 15 * time.Second},
		"tcp", hostport,
		&tls.Config{
			ServerName: hostname,
			NextProtos: []string{"http/1.1"},
		},
	)
	if err != nil {
		return err
	}
	defer up.Close()

	if err := req.Write(up); err != nil {
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(up), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return resp.Write(dst)
}

func (p *proxy) inspectAndStore(req *http.Request, host string, body []byte) {
	if len(body) == 0 {
		return
	}
	prompts := ExtractPrompts(body)
	if len(prompts) == 0 {
		return
	}

	// Join all message contents into one string so we get a single flag entry
	// per HTTP request rather than one per message in the conversation history.
	combined := strings.Join(prompts, "\n\n")
	matches := p.eng.Inspect(combined)
	if len(matches) == 0 {
		return
	}

	err := p.db.SaveFlag(store.FlaggedPrompt{
		Timestamp: time.Now(),
		Host:      stripPort(host),
		Path:      req.URL.Path,
		Prompt:    combined,
		Matches:   matches,
	})
	if err != nil {
		log.Printf("store: %v", err)
	} else {
		log.Printf("FLAG: %s%s — %d rule(s) hit", stripPort(host), req.URL.Path, len(matches))
	}
}

// handlePlainHTTP proxies plain HTTP requests (non-CONNECT).
func (p *proxy) handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	r.RequestURI = ""
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// tunnel blindly copies bytes between client and upstream (non-intercepted CONNECT).
func tunnel(client net.Conn, hostport string) {
	defer client.Close()
	up, err := net.DialTimeout("tcp", hostport, 15*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, client); done <- struct{}{} }()
	go func() { io.Copy(client, up); done <- struct{}{} }()
	<-done
}

func stripPort(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}
