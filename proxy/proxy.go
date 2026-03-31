package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
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
	ca            *CA
	db            *store.Store
	eng           *inspector.Engine
	upstreamProxy string // optional: "http://host:port" or "http://user:pass@host:port"
}

// Start runs the HTTP proxy on the given port. Blocks until error.
// upstreamProxy is optional — set to route outbound traffic through a corporate proxy.
func Start(port int, ca *CA, db *store.Store, eng *inspector.Engine, upstreamProxy string) error {
	p := &proxy{ca: ca, db: db, eng: eng, upstreamProxy: upstreamProxy}
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
		p.tunnel(clientConn, r.Host)
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

		log.Printf("REQUEST: %s %s%s body=%d bytes stream=%v", req.Method, stripPort(hostport), req.URL.Path, len(body), IsStreaming(body))
		prompts := ExtractPrompts(body)
		displayPrompt := ExtractUserQuery(body)
		log.Printf("EXTRACTED: %d prompt(s)", len(prompts))
		log.Printf("  query: %.120s", displayPrompt)
		if len(prompts) == 0 && len(body) > 0 && len(body) < 4096 && (body[0] == '{' || body[0] == '[') {
			end := 2000
			if len(body) < end {
				end = len(body)
			}
			log.Printf("BODY SAMPLE: %s", string(body[:end]))
		}

		// Redact track-mode matches from the full inspection text, then
		// replace each matched value in the raw body before forwarding.
		combined := strings.Join(prompts, "\n\n")
		redactedCombined, redactions := p.eng.RedactText(combined)
		redactedBody := body
		if len(redactions) > 0 {
			redactedBody = p.eng.RedactBodyForForwarding(body)
			req.Body = io.NopCloser(bytes.NewReader(redactedBody))
			req.ContentLength = int64(len(redactedBody))
		}

		// Background Copilot requests (title, summary, progress messages) must
		// never be blocked — their responses surface directly in the chat UI, so
		// a block response from us appears as a spurious chat message. We still
		// inspect and redact them; we just don't terminate the connection.
		allowBlock := !isCopilotBackground(body)

		if blocked, msg := p.inspectAndStore(req, hostport, combined, redactedCombined, displayPrompt, redactions, allowBlock); blocked {
			writeBlockedResponse(tlsClient, msg, IsStreaming(body), req.URL.Path)
			return
		}

		// Forward to real upstream and pipe response back
		if err := p.forward(tlsClient, req, hostport); err != nil {
			return
		}
	}
}

// dialUpstream opens a TCP connection to hostport, routing through the
// corporate proxy when configured. For HTTPS targets it sends HTTP CONNECT
// to the upstream proxy and returns the tunnel connection.
func (p *proxy) dialUpstream(hostport string) (net.Conn, error) {
	if p.upstreamProxy == "" {
		return net.DialTimeout("tcp", hostport, 15*time.Second)
	}

	u, err := url.Parse(p.upstreamProxy)
	if err != nil {
		return nil, fmt.Errorf("upstream proxy URL: %w", err)
	}
	proxyAddr := u.Host
	if u.Port() == "" {
		proxyAddr = u.Hostname() + ":8080"
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial upstream proxy: %w", err)
	}

	// Send CONNECT to the upstream proxy to open a tunnel to the real target.
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: hostport},
		Host:   hostport,
		Header: make(http.Header),
	}
	if u.User != nil {
		user := u.User.Username()
		pass, _ := u.User.Password()
		req.Header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT response: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT: %s", resp.Status)
	}
	return conn, nil
}

// forward dials the real upstream, sends the request, and writes the response back to dst.
func (p *proxy) forward(dst net.Conn, req *http.Request, hostport string) error {
	hostname := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		hostname = h
	}

	tcpConn, err := p.dialUpstream(hostport)
	if err != nil {
		return err
	}
	up := tls.Client(tcpConn, &tls.Config{
		ServerName: hostname,
		NextProtos: []string{"http/1.1"},
	})
	if err := up.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		tcpConn.Close()
		return err
	}
	if err := up.Handshake(); err != nil {
		tcpConn.Close()
		return err
	}
	up.SetDeadline(time.Time{})
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

// isCopilotBackground reports whether the request body is a Copilot-internal
// background call (title generation, summarization, progress messages).
// These requests contain full conversation history and their responses appear
// inline in the chat UI — so we must never block them.
func isCopilotBackground(body []byte) bool {
	var env struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if json.Unmarshal(body, &env) != nil {
		return false
	}
	for _, m := range env.Messages {
		t := strings.TrimSpace(m.Content)
		if strings.HasPrefix(t, "Summarize the following") ||
			strings.HasPrefix(t, "Please write a brief title") ||
			strings.HasPrefix(t, "Please generate exactly") {
			return true
		}
	}
	return false
}

// inspectAndStore stores every intercepted prompt.
// redactions are track-mode matches already applied to the forwarded body.
// allowBlock: if false, block-mode rules are recorded but the request is not terminated.
// Returns (blocked, assistantMessage).
func (p *proxy) inspectAndStore(req *http.Request, host, combined, redactedCombined, displayPrompt string, redactions []inspector.Match, allowBlock bool) (bool, string) {
	if combined == "" && len(redactions) == 0 {
		return false, ""
	}

	result := p.eng.Inspect(combined)

	// Merge block-mode matches with redactions for storage.
	allMatches := append(result.Matches, redactions...)

	status := store.StatusClean
	if result.Blocked && allowBlock {
		status = store.StatusBlocked
	} else if result.Blocked || len(redactions) > 0 {
		status = store.StatusRedacted
	} else if len(result.Matches) > 0 {
		status = store.StatusFlagged
	}

	// Store the user's display prompt; fall back to combined if empty.
	storedPrompt := displayPrompt
	if storedPrompt == "" {
		storedPrompt = combined
	}
	redactedDisplay, _ := p.eng.RedactText(storedPrompt)

	log.Printf("STORE: status=%s host=%s rules=%d", status, stripPort(host), len(allMatches))
	err := p.db.SavePrompt(store.Prompt{
		Timestamp:      time.Now(),
		Host:           stripPort(host),
		Path:           req.URL.Path,
		Prompt:         storedPrompt,
		RedactedPrompt: redactedDisplay,
		Status:         status,
		Matches:        allMatches,
	})
	if err != nil {
		log.Printf("store ERROR: %v", err)
	} else if status != store.StatusClean {
		names := make([]string, 0, len(allMatches))
		for _, m := range allMatches {
			names = append(names, m.RuleName)
		}
		log.Printf("%s: %s%s — %s", strings.ToUpper(string(status)), stripPort(host), req.URL.Path, strings.Join(names, ", "))
	}

	if !result.Blocked || !allowBlock {
		return false, ""
	}

	var ruleNames []string
	for _, m := range result.Matches {
		if m.Mode == "block" {
			ruleNames = append(ruleNames, m.RuleName)
		}
	}
	msg := "⚠️ **Prompt Guard blocked this request.**\n\n" +
		"Your prompt contained sensitive information detected by the following rule(s):\n"
	for _, name := range ruleNames {
		msg += "- " + name + "\n"
	}
	msg += "\nThis request was **not forwarded** to the AI. Please remove the sensitive data and try again."
	return true, msg
}

// writeBlockedResponse returns a well-formed response so the client renders
// the blocked message in the chat UI.
// Anthropic (/v1/messages) and OpenAI (/chat/completions) have different
// streaming formats; non-streaming also differs.
func writeBlockedResponse(conn net.Conn, assistantMsg string, streaming bool, path string) {
	if strings.Contains(path, "/v1/messages") {
		// Anthropic event-stream format.
		if streaming {
			msgStart := `{"type":"message_start","message":{"id":"msg_blocked","type":"message","role":"assistant","content":[],"model":"claude-haiku-4.5","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":0,"output_tokens":0}}}`
			cbStart := `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`
			cbDelta := fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%s}}`, jsonString(assistantMsg))
			cbStop := `{"type":"content_block_stop","index":0}`
			msgDelta := `{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":1}}`
			msgStop := `{"type":"message_stop"}`
			body := "event: message_start\ndata: " + msgStart + "\n\n" +
				"event: content_block_start\ndata: " + cbStart + "\n\n" +
				"event: content_block_delta\ndata: " + cbDelta + "\n\n" +
				"event: content_block_stop\ndata: " + cbStop + "\n\n" +
				"event: message_delta\ndata: " + msgDelta + "\n\n" +
				"event: message_stop\ndata: " + msgStop + "\n\n"
			fmt.Fprintf(conn,
				"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n%s",
				body,
			)
		} else {
			body := fmt.Sprintf(
				`{"id":"msg_blocked","type":"message","role":"assistant","content":[{"type":"text","text":%s}],"model":"claude-haiku-4.5","stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":0,"output_tokens":1}}`,
				jsonString(assistantMsg),
			)
			fmt.Fprintf(conn,
				"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
				len(body), body,
			)
		}
		return
	}

	// OpenAI format (chat/completions and everything else).
	if streaming {
		chunk := fmt.Sprintf(
			`{"id":"chatcmpl-blocked","object":"chat.completion.chunk","created":0,"model":"prompt-guard",`+
				`"choices":[{"index":0,"delta":{"role":"assistant","content":%s},"finish_reason":null}]}`,
			jsonString(assistantMsg),
		)
		done := `{"id":"chatcmpl-blocked","object":"chat.completion.chunk","created":0,"model":"prompt-guard",` +
			`"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`
		body := "data: " + chunk + "\n\ndata: " + done + "\n\ndata: [DONE]\n\n"
		fmt.Fprintf(conn,
			"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n%s",
			body,
		)
	} else {
		body := fmt.Sprintf(
			`{"id":"chatcmpl-blocked","object":"chat.completion","created":0,"model":"prompt-guard",`+
				`"choices":[{"index":0,"message":{"role":"assistant","content":%s},"finish_reason":"stop"}],`+
				`"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}`,
			jsonString(assistantMsg),
		)
		fmt.Fprintf(conn,
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			len(body), body,
		)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
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
func (p *proxy) tunnel(client net.Conn, hostport string) {
	defer client.Close()
	up, err := p.dialUpstream(hostport)
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, client); done <- struct{}{} }()
	go func() { io.Copy(client, up); done <- struct{}{} }()
	<-done
	<-done
}

func stripPort(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}
