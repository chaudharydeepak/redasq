package proxy

import (
	"bufio"
	"bytes"
	"context"
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
	"sync"
	"time"

	"github.com/chaudharydeepak/redasq/inspector"
	"github.com/chaudharydeepak/redasq/mlclient"
	"github.com/chaudharydeepak/redasq/store"
)

var (
	mlFirstOK   sync.Once
	mlFirstFail sync.Once
)

// Debug enables verbose request/connection logging. Set from main via --debug flag.
var Debug bool

func debugf(format string, args ...any) {
	if Debug {
		log.Printf(format, args...)
	}
}

// targetSuffixes are the hostname suffixes we intercept.
// All traffic to matching hosts is inspected regardless of path.
var targetSuffixes = []string{
	"api.openai.com",
	"api.anthropic.com",
	"api.githubcopilot.com",
	"copilot-proxy.githubusercontent.com",
	".githubcopilot.com",
	".openai.com",
	".anthropic.com",
	"claude.ai",
}

type proxy struct {
	ca            *CA
	db            *store.Store
	eng           *inspector.Engine
	ml            *mlclient.Client
	upstreamProxy string
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

// Start runs the HTTP proxy on the given port. Blocks until error.
// upstreamProxy is optional — set to route outbound traffic through a corporate proxy.
// ml is optional — when non-nil, every intercepted prompt is also classified
// in parallel with forwarding and the result is written back to the prompt row.
func Start(port int, ca *CA, db *store.Store, eng *inspector.Engine, ml *mlclient.Client, upstreamProxy string) error {
	p := &proxy{ca: ca, db: db, eng: eng, ml: ml, upstreamProxy: upstreamProxy}
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: p,
	}
	debugf("proxy: listening on :%d", port)
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
		debugf("CONNECT %s (intercepting)", r.Host)
		p.mitm(clientConn, r.Host)
	} else {
		debugf("CONNECT %s (tunnelling)", r.Host)
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

		// Parse once — all fields derived from a single unmarshal pass.
		parsed := ParseRequest(body)

		debugf("REQUEST: %s %s%s body=%d bytes stream=%v accept=%s", req.Method, stripPort(hostport), req.URL.Path, len(body), parsed.Streaming, req.Header.Get("Accept"))
		if Debug {
			for _, h := range []string{"X-Request-Id", "Vscode-Sessionid", "Vscode-Machineid", "X-Github-Api-Version", "X-Client-Session-Id", "User-Agent", "Copilot-Integration-Id"} {
				if v := req.Header.Get(h); v != "" {
					debugf("  HEADER %s: %s", h, v)
				}
			}
		}

		// Session ID + client: extracted from headers where available, falling back
		// to the Anthropic metadata.user_id field parsed by ParseRequest.
		// Copilot VSCode extension: Vscode-Sessionid header.
		// Copilot CLI: X-Client-Session-Id header; Copilot-Integration-Id names the client.
		// Claude Code: metadata.user_id JSON field; User-Agent names the client.
		// All others: first token of User-Agent as best-effort client name.
		var sessionID, client string
		if sid := req.Header.Get("Vscode-Sessionid"); sid != "" {
			sessionID = sid
			client = req.Header.Get("User-Agent")
			debugf("SESSION (copilot-vscode): %s", sid)
		} else if sid := req.Header.Get("X-Client-Session-Id"); sid != "" {
			sessionID = sid
			client = req.Header.Get("Copilot-Integration-Id")
			if client == "" {
				client = req.Header.Get("User-Agent")
			}
			debugf("SESSION (copilot-cli): %s", sid)
		} else if parsed.SessionID != "" {
			sessionID = parsed.SessionID
			client = req.Header.Get("User-Agent")
			debugf("SESSION (claude): %s", sessionID)
		}
		// Trim client to first space-delimited token to keep it short.
		if i := strings.IndexByte(client, ' '); i > 0 {
			client = client[:i]
		}

		// Detect and store telemetry/analytics payloads separately.
		if isTelemetry(body) {
			_, summary := extractTelemetryInfo(body)
			debugf("TELEMETRY: %s", summary)
			_, _ = p.db.SavePrompt(store.Prompt{
				Timestamp: time.Now(),
				Host:      stripPort(hostport),
				Path:      req.URL.Path,
				Prompt:    summary,
				Status:    store.StatusTelemetry,
			})
			p.forward(tlsClient, req, hostport) //nolint:errcheck
			continue
		}

		debugf("EXTRACTED: %d prompt(s)", len(parsed.Prompts))
		debugf("  query: %.120s", parsed.UserQuery)
		if Debug {
			for i, seg := range parsed.Prompts {
				end := 300
				if len(seg) < end {
					end = len(seg)
				}
				debugf("  PROMPT[%d] (%d chars): %.300s", i, len(seg), seg)
			}
		}
		if Debug && len(parsed.Prompts) == 0 && len(body) > 0 && (body[0] == '{' || body[0] == '[') {
			// Print top-level keys to understand the body shape without dumping 93KB.
			var top map[string]json.RawMessage
			if json.Unmarshal(body, &top) == nil {
				keys := make([]string, 0, len(top))
				for k, v := range top {
					snippet := string(v)
					if len(snippet) > 80 {
						snippet = snippet[:80] + "..."
					}
					keys = append(keys, k+"="+snippet)
				}
				debugf("BODY KEYS: %s", strings.Join(keys, " | "))
			} else {
				end := 500
				if len(body) < end {
					end = len(body)
				}
				debugf("BODY SAMPLE (non-JSON): %s", string(body[:end]))
			}
		}

		// Redact track-mode matches from the full inspection text, then
		// replace each matched value in the raw body before forwarding.
		combined := strings.Join(parsed.Prompts, "\n\n")
		redactedCombined, redactions := p.eng.RedactText(combined)
		redactedBody := body
		if len(redactions) > 0 {
			candidate := p.eng.RedactBodyForForwarding(body)
			// Safety net: if the body was valid JSON but redaction produced invalid
			// JSON, fall back to the original to avoid a bad-request loop. The
			// dashboard still shows the redacted version; only the forwarded bytes
			// are preserved as-is.
			if json.Valid(body) && !json.Valid(candidate) {
				log.Printf("warn: redaction produced invalid JSON body — forwarding original")
				candidate = body
			}
			redactedBody = candidate
			req.Body = io.NopCloser(bytes.NewReader(redactedBody))
			req.ContentLength = int64(len(redactedBody))
		}

		// Background Copilot requests (title, summary, progress messages) must
		// never be blocked — their responses surface directly in the chat UI, so
		// a block response from us appears as a spurious chat message. We still
		// inspect and redact them; we just don't terminate the connection.
		allowBlock := !parsed.Background

		// Display prompt: for tool-chain continuation requests there's no new
		// user-typed text — show a clear marker rather than the parent turn's
		// text (would look like a duplicate row) or the system-prompt soup
		// (the legacy fallback). Regex inspection still runs on `combined` so
		// sensitive data leaking through tool output is still caught.
		displayPrompt := parsed.UserQuery
		if parsed.IsContinuation {
			displayPrompt = "↳ tool continuation"
		}

		blocked, msg, savedID, status := p.inspectAndStore(req, hostport, combined, redactedCombined, displayPrompt, redactions, allowBlock, sessionID, client, parsed.Model)

		// Fire classifier in parallel with the upstream call. We feed user-typed
		// text first, falling back to current-turn content (tool_result bodies,
		// function_call outputs, etc.) so anything regex inspects also gets ML
		// coverage. The system prompt is deliberately excluded — it's huge
		// boilerplate that drowns the signal in DistilBERT's 512-token window.
		const mlMaxChars = 4000
		mlText := parsed.UserQuery
		if mlText == "" {
			mlText = parsed.CurrentTurn
		}
		if savedID > 0 && p.ml != nil && mlText != "" {
			if len(mlText) > mlMaxChars {
				mlText = mlText[:mlMaxChars]
			}
			go p.classifyAndStore(savedID, mlText)
		}

		if blocked {
			if strings.Contains(stripPort(hostport), "claude.ai") {
				writeHTTPError(tlsClient, 400, msg)
			} else {
				writeBlockedResponse(tlsClient, msg, parsed.Streaming, req.URL.Path)
			}
			return
		}

		// Forward to real upstream and pipe response back.
		// Measure TTFB (request sent → response headers received) and persist it.
		ttfb, inTok, outTok, respBytes, err := p.forward(tlsClient, req, hostport)
		if savedID > 0 {
			p.db.UpdateDuration(savedID, ttfb.Milliseconds())
			if inTok > 0 || outTok > 0 {
				p.db.UpdateTokens(savedID, inTok, outTok)
			}
			// Store LLM response for compliance when request was redacted (track-mode rules fired).
			if status == store.StatusRedacted && len(respBytes) > 0 {
				p.db.UpdateLLMResponse(savedID, ExtractResponseText(respBytes))
			}
		}
		if err != nil {
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
// Returns the time-to-first-byte, token usage, raw response bytes (capped at 2KB), and any error.
func (p *proxy) forward(dst net.Conn, req *http.Request, hostport string) (time.Duration, int, int, []byte, error) {
	hostname := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		hostname = h
	}

	tcpConn, err := p.dialUpstream(hostport)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	up := tls.Client(tcpConn, &tls.Config{
		ServerName: hostname,
		NextProtos: []string{"http/1.1"},
	})
	if err := up.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		tcpConn.Close()
		return 0, 0, 0, nil, err
	}
	if err := up.Handshake(); err != nil {
		tcpConn.Close()
		return 0, 0, 0, nil, err
	}
	up.SetDeadline(time.Time{})
	defer up.Close()

	// Remove Accept-Encoding so upstream responds with plain text.
	// This lets our TeeReader capture readable SSE for token parsing.
	req.Header.Del("Accept-Encoding")

	start := time.Now()
	if err := req.Write(up); err != nil {
		return 0, 0, 0, nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(up), req)
	ttfb := time.Since(start)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	defer resp.Body.Close()

	// Tee response body to capture usage without blocking the stream.
	var buf bytes.Buffer
	resp.Body = io.NopCloser(io.TeeReader(resp.Body, &buf))
	writeErr := resp.Write(dst)
	// If the client closed early, drain remaining upstream bytes so we still
	// capture the final message_delta event that carries the usage counts.
	if writeErr != nil {
		io.Copy(io.Discard, resp.Body)
	}
	raw := buf.Bytes()
	in, out := ExtractUsage(raw)
	debugf("USAGE: input=%d output=%d", in, out)

	// Capture the full response for compliance text extraction.
	// ExtractResponseText caps the extracted plain text at 2KB — we don't limit raw bytes here
	// because SSE envelopes are verbose and a 2KB response may span many kilobytes of raw stream.
	const maxResponseStore = 512 * 1024 // 512KB raw cap — safety net only
	var respSnippet []byte
	if len(raw) > 0 {
		end := len(raw)
		if end > maxResponseStore {
			end = maxResponseStore
		}
		respSnippet = make([]byte, end)
		copy(respSnippet, raw[:end])
	}
	return ttfb, in, out, respSnippet, writeErr
}

// isTelemetry reports whether the body is an analytics/telemetry payload
// (Segment, Amplitude, Datadog RUM, etc.) rather than an AI prompt.
func isTelemetry(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var env struct {
		WriteKey string        `json:"writeKey"`
		Batch    []interface{} `json:"batch"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return false
	}
	return env.WriteKey != "" && len(env.Batch) > 0
}

// extractTelemetryInfo pulls event names and PII fields from a Segment batch payload.
func extractTelemetryInfo(body []byte) (events []string, summary string) {
	var env struct {
		WriteKey string `json:"writeKey"`
		Batch    []struct {
			Event      string                 `json:"event"`
			Type       string                 `json:"type"`
			Properties map[string]interface{} `json:"properties"`
			Context    struct {
				Traits map[string]interface{} `json:"traits"`
			} `json:"context"`
		} `json:"batch"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, ""
	}

	seen := map[string]bool{}
	var piiFields []string
	piiKeys := []string{"email", "userId", "user_id", "anonymousId", "ip", "phone", "name"}

	for _, item := range env.Batch {
		if item.Event != "" && !seen[item.Event] {
			events = append(events, item.Event)
			seen[item.Event] = true
		}
		// Check traits for PII
		for _, key := range piiKeys {
			if v, ok := item.Context.Traits[key]; ok && v != "" && v != nil {
				found := false
				for _, f := range piiFields {
					if f == key {
						found = true
						break
					}
				}
				if !found {
					piiFields = append(piiFields, key)
				}
			}
		}
	}

	parts := []string{"Events: " + strings.Join(events, ", ")}
	if len(piiFields) > 0 {
		parts = append(parts, "PII fields: "+strings.Join(piiFields, ", "))
	}
	return events, strings.Join(parts, " | ")
}


// classifyAndStore runs the prompt through the classifier sidecar and writes
// the JSON-encoded prediction back to the prompt row. Failures are logged
// at debug level only — ML is opinion-only, so an outage must not affect traffic.
// The first success and first failure are also logged at info level so the
// operator can see the integration is live without enabling --debug.
func (p *proxy) classifyAndStore(id int64, text string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pred, err := p.ml.Classify(ctx, text)
	if err != nil {
		mlFirstFail.Do(func() {
			log.Printf("ml: first classify failed (id=%d): %v — predictions will be missing until sidecar is reachable", id, err)
		})
		debugf("ml: classify id=%d: %v", id, err)
		return
	}
	b, err := json.Marshal(pred)
	if err != nil {
		debugf("ml: marshal id=%d: %v", id, err)
		return
	}
	if err := p.db.UpdateMLPrediction(id, string(b)); err != nil {
		debugf("ml: update id=%d: %v", id, err)
		return
	}
	mlFirstOK.Do(func() {
		log.Printf("ml: live (id=%d top=%s score=%.2f latency=%dms)", id, pred.TopLabel, pred.TopScore, pred.LatencyMS)
	})
	debugf("ml: id=%d top=%s score=%.3f labels=%v latency=%dms", id, pred.TopLabel, pred.TopScore, pred.AboveThreshold, pred.LatencyMS)
}

// inspectAndStore stores every intercepted prompt.
// redactions are track-mode matches already applied to the forwarded body.
// allowBlock: if false, block-mode rules are recorded but the request is not terminated.
// Returns (blocked, assistantMessage, savedRowID, status). savedRowID is 0 if nothing was stored.
func (p *proxy) inspectAndStore(req *http.Request, host, combined, redactedCombined, displayPrompt string, redactions []inspector.Match, allowBlock bool, sessionID, client, model string) (bool, string, int64, store.Status) {
	if combined == "" && len(redactions) == 0 {
		return false, "", 0, store.StatusClean
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
	// Redact a copy for the RedactedPrompt field so the UI can show before/after.
	redactedDisplay, _ := p.eng.RedactText(storedPrompt)

	debugf("STORE: status=%s host=%s rules=%d", status, stripPort(host), len(allMatches))
	savedID, err := p.db.SavePrompt(store.Prompt{
		Timestamp:      time.Now(),
		Host:           stripPort(host),
		Path:           req.URL.Path,
		Prompt:         storedPrompt,
		RedactedPrompt: redactedDisplay,
		Status:         status,
		Matches:        allMatches,
		AgentMode:      p.eng.AgentMode(),
		SessionID:      sessionID,
		Client:         client,
		Model:          model,
	})
	if err != nil {
		log.Printf("store ERROR: %v", err)
		savedID = 0
	} else if status != store.StatusClean {
		names := make([]string, 0, len(allMatches))
		for _, m := range allMatches {
			names = append(names, m.RuleName)
		}
		log.Printf("%s: %s%s — %s", strings.ToUpper(string(status)), stripPort(host), req.URL.Path, strings.Join(names, ", "))
	}

	if !result.Blocked || !allowBlock {
		return false, "", savedID, status
	}

	var ruleNames []string
	for _, m := range result.Matches {
		if m.Mode == "block" {
			ruleNames = append(ruleNames, m.RuleName)
		}
	}
	msg := "⚠️ **Redasq blocked this request.**\n\n" +
		"Your prompt contained sensitive information detected by the following rule(s):\n"
	for _, name := range ruleNames {
		msg += "- " + name + "\n"
	}
	msg += "\nThis request was **not forwarded** to the AI. Please remove the sensitive data and try again."
	return true, msg, savedID, status
}

// writeHTTPError writes a plain HTTP error response for non-API clients (e.g. claude.ai web).
func writeHTTPError(conn net.Conn, code int, msg string) {
	b, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{Error: msg})
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(b), b)
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
			cbDeltaB, _ := json.Marshal(struct {
				Type  string `json:"type"`
				Index int    `json:"index"`
				Delta struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"delta"`
			}{Type: "content_block_delta", Delta: struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}{Type: "text_delta", Text: assistantMsg}})
			cbDelta := string(cbDeltaB)
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
			b, _ := json.Marshal(struct {
				ID           string `json:"id"`
				Type         string `json:"type"`
				Role         string `json:"role"`
				Content      []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
				Model        string      `json:"model"`
				StopReason   string      `json:"stop_reason"`
				StopSequence interface{} `json:"stop_sequence"`
				Usage        struct {
					InputTokens  int `json:"input_tokens"`
					OutputTokens int `json:"output_tokens"`
				} `json:"usage"`
			}{
				ID: "msg_blocked", Type: "message", Role: "assistant",
				Content:    []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				}{{Type: "text", Text: assistantMsg}},
				Model: "claude-haiku-4.5", StopReason: "end_turn", StopSequence: nil,
				Usage: struct {
					InputTokens  int `json:"input_tokens"`
					OutputTokens int `json:"output_tokens"`
				}{OutputTokens: 1},
			})
			fmt.Fprintf(conn,
				"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
				len(b), b,
			)
		}
		return
	}

	// OpenAI format (chat/completions and everything else).
	if streaming {
		chunkB, _ := json.Marshal(struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			Created int    `json:"created"`
			Model   string `json:"model"`
			Choices []struct {
				Index        int    `json:"index"`
				Delta        struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason interface{} `json:"finish_reason"`
			} `json:"choices"`
		}{
			ID: "chatcmpl-blocked", Object: "chat.completion.chunk", Model: "redasq",
			Choices: []struct {
				Index        int    `json:"index"`
				Delta        struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason interface{} `json:"finish_reason"`
			}{{Delta: struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			}{Role: "assistant", Content: assistantMsg}}},
		})
		done := `{"id":"chatcmpl-blocked","object":"chat.completion.chunk","created":0,"model":"redasq",` +
			`"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`
		body := "data: " + string(chunkB) + "\n\ndata: " + done + "\n\ndata: [DONE]\n\n"
		fmt.Fprintf(conn,
			"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n%s",
			body,
		)
	} else {
		b, _ := json.Marshal(struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			Created int    `json:"created"`
			Model   string `json:"model"`
			Choices []struct {
				Index        int    `json:"index"`
				Message      struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				} `json:"message"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Usage struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
				TotalTokens      int `json:"total_tokens"`
			} `json:"usage"`
		}{
			ID: "chatcmpl-blocked", Object: "chat.completion", Model: "redasq",
			Choices: []struct {
				Index        int    `json:"index"`
				Message      struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				} `json:"message"`
				FinishReason string `json:"finish_reason"`
			}{{Message: struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			}{Role: "assistant", Content: assistantMsg}, FinishReason: "stop"}},
		})
		fmt.Fprintf(conn,
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			len(b), b,
		)
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
