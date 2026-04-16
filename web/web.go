package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/chaudharydeepak/prompt-guard/inspector"
	"github.com/chaudharydeepak/prompt-guard/store"
)

// NewHandler builds and returns the dashboard HTTP handler without starting a server.
// Used directly in tests via httptest.NewServer.
func NewHandler(db *store.Store, eng *inspector.Engine, configPath string) http.Handler {
	mux := http.NewServeMux()
	registerRoutes(mux, db, eng, configPath)
	return mux
}

// Start runs the web dashboard on the given port. Non-blocking.
func Start(port int, db *store.Store, eng *inspector.Engine, configPath string) {
	mux := http.NewServeMux()
	registerRoutes(mux, db, eng, configPath)
	srv := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: mux}
	log.Printf("dashboard: http://localhost:%d", port)
	go func() { log.Fatal(srv.ListenAndServe()) }()
}

func registerRoutes(mux *http.ServeMux, db *store.Store, eng *inspector.Engine, configPath string) {
	mux.HandleFunc("/api/prompts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			if err := db.DeleteAllPrompts(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		apiPrompts(w, r, db)
	})
	mux.HandleFunc("/api/prompts/", func(w http.ResponseWriter, r *http.Request) {
		apiPromptDetail(w, r, db)
	})
	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		apiRules(w, r, eng)
	})
	mux.HandleFunc("/api/rules/", func(w http.ResponseWriter, r *http.Request) {
		apiRuleMode(w, r, db, eng, configPath)
	})
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		apiStats(w, r, db)
	})
	mux.HandleFunc("/api/model-stats", func(w http.ResponseWriter, r *http.Request) {
		stats, err := db.ModelStats()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonResponse(w, stats)
	})
	mux.HandleFunc("/api/agent-mode", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			next := !eng.AgentMode()
			eng.SetAgentMode(next)
			val := "false"
			if next {
				val = "true"
			}
			db.SetSetting("agent_mode", val)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"agent_mode":%v}`, eng.AgentMode())
	})
	mux.HandleFunc("/api/context-limits", func(w http.ResponseWriter, r *http.Request) {
		cfg, err := inspector.LoadConfig(configPath)
		limits := map[string]int{"default": 200000}
		if err == nil && len(cfg.ContextLimits) > 0 {
			limits = cfg.ContextLimits
			if _, ok := limits["default"]; !ok {
				limits["default"] = 200000
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(limits)
	})
	mux.HandleFunc("/api/export", func(w http.ResponseWriter, r *http.Request) {
		apiExport(w, r, db)
	})
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		apiScan(w, r, eng)
	})
	mux.HandleFunc("/favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "no-cache")
		fmt.Fprint(w, logoSVG)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, dashboardHTML)
	})
}

// ── API handlers ─────────────────────────────────────────────────────────────

func apiPrompts(w http.ResponseWriter, r *http.Request, db *store.Store) {
	statusFilter := r.URL.Query().Get("status")
	search := r.URL.Query().Get("search")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 200 {
		perPage = 25
	}
	offset := (page - 1) * perPage

	total, err := db.CountPrompts(statusFilter, search)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	prompts, err := db.ListPrompts(statusFilter, search, perPage, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type row struct {
		ID             int64             `json:"id"`
		Time           string            `json:"time"`
		Host           string            `json:"host"`
		Path           string            `json:"path"`
		Status         string            `json:"status"`
		Rules          []string          `json:"rules"`
		Severity       string            `json:"severity"`
		Matches        []inspector.Match `json:"matches"`
		Prompt         string            `json:"prompt"`
		RedactedPrompt string            `json:"redacted_prompt,omitempty"`
		DurationMS     int64             `json:"duration_ms"`
		AgentMode      bool              `json:"agent_mode"`
		InputTokens    int               `json:"input_tokens"`
		OutputTokens   int               `json:"output_tokens"`
		SessionID      string            `json:"session_id"`
		Client         string            `json:"client"`
		Model          string            `json:"model"`
	}
	out := make([]row, 0, len(prompts))
	for _, p := range prompts {
		rules := make([]string, 0, len(p.Matches))
		maxSev := ""
		for _, m := range p.Matches {
			rules = append(rules, m.RuleName)
			if m.Severity == "high" {
				maxSev = "high"
			} else if m.Severity == "medium" && maxSev != "high" {
				maxSev = "medium"
			} else if maxSev == "" {
				maxSev = m.Severity
			}
		}
		out = append(out, row{
			ID:             p.ID,
			Time:           p.Timestamp.Format("Jan 02 15:04:05"),
			Host:           p.Host,
			Path:           p.Path,
			Status:         string(p.Status),
			Rules:          rules,
			Severity:       maxSev,
			Matches:        p.Matches,
			Prompt:         truncate(p.Prompt, 400),
			RedactedPrompt: truncate(p.RedactedPrompt, 400),
			DurationMS:     p.DurationMS,
			AgentMode:      p.AgentMode,
			InputTokens:    p.InputTokens,
			OutputTokens:   p.OutputTokens,
			SessionID:      p.SessionID,
			Client:         p.Client,
			Model:          p.Model,
		})
	}
	type response struct {
		Items   []row `json:"items"`
		Total   int   `json:"total"`
		Page    int   `json:"page"`
		PerPage int   `json:"per_page"`
	}
	jsonResponse(w, response{Items: out, Total: total, Page: page, PerPage: perPage})
}

func apiPromptDetail(w http.ResponseWriter, r *http.Request, db *store.Store) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	p, err := db.GetPrompt(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	jsonResponse(w, p)
}

// POST /api/rules/{id}/mode  body: {"mode":"track"|"block"}
func apiRuleMode(w http.ResponseWriter, r *http.Request, db *store.Store, eng *inspector.Engine, configPath string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// path: /api/rules/{id}/mode
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		http.NotFound(w, r)
		return
	}
	ruleID := parts[2]
	var body struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || (body.Mode != "track" && body.Mode != "block" && body.Mode != "redact") {
		http.Error(w, "invalid mode", http.StatusBadRequest)
		return
	}
	if !eng.SetMode(ruleID, inspector.Mode(body.Mode)) {
		http.NotFound(w, r)
		return
	}
	// Config file is source of truth — write there first.
	if err := inspector.UpdateConfigMode(configPath, ruleID, body.Mode); err != nil {
		http.Error(w, "failed to update rules.json: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Keep DB in sync.
	if err := db.SetRuleMode(ruleID, body.Mode); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func apiRules(w http.ResponseWriter, _ *http.Request, eng *inspector.Engine) {
	type ruleOut struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		Mode        string `json:"mode"`
	}
	rules := eng.Rules()
	out := make([]ruleOut, len(rules))
	for i, r := range rules {
		out[i] = ruleOut{r.ID, r.Name, r.Description, string(r.Severity), string(r.Mode)}
	}
	// Sort: high → medium → low, then alphabetically by name within each group.
	sevOrder := map[string]int{"high": 0, "medium": 1, "low": 2}
	slices.SortFunc(out, func(a, b ruleOut) int {
		if sa, sb := sevOrder[a.Severity], sevOrder[b.Severity]; sa != sb {
			return sa - sb
		}
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	jsonResponse(w, out)
}

func apiStats(w http.ResponseWriter, _ *http.Request, db *store.Store) {
	jsonResponse(w, db.Stats())
}

// apiExport writes prompts as a plain-text file for LLM analysis.
// Optional query params: from=YYYY-MM-DD, to=YYYY-MM-DD
// Secrets are never exported — redacted text is used when available.
func apiExport(w http.ResponseWriter, r *http.Request, db *store.Store) {
	var from, to time.Time
	if s := r.URL.Query().Get("from"); s != "" {
		if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
			from = t
		}
	}
	if s := r.URL.Query().Get("to"); s != "" {
		if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
			to = t.Add(24*time.Hour - time.Second) // inclusive: end of day
		}
	}

	prompts, err := db.ExportPrompts(from, to)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(
		`attachment; filename="prompt-guard-export-%s.txt"`,
		time.Now().Format("2006-01-02"),
	))

	// Count blocked/redacted for context in the system prompt
	blocked, redacted := 0, 0
	for _, p := range prompts {
		switch p.Status {
		case store.StatusBlocked:
			blocked++
		case store.StatusRedacted:
			redacted++
		}
	}

	fromStr, toStr := "beginning", "now"
	if !from.IsZero() {
		fromStr = from.Format("2006-01-02")
	}
	if !to.IsZero() {
		toStr = to.Format("2006-01-02")
	}

	fmt.Fprintf(w, `You are analyzing a developer's AI coding assistant usage log captured by Prompt Guard,
a local HTTPS proxy that intercepts prompts sent to AI services (GitHub Copilot, OpenAI, Anthropic).
Sensitive values (API keys, passwords, PII) have been replaced with [REDACTED] before this export.

This export covers %s → %s and contains %d prompts (%d blocked, %d redacted).

Please analyse this data and provide:
1. USAGE PATTERNS — what tasks and topics dominate? What languages or frameworks appear most?
2. DATA HYGIENE — are there recurring patterns of sensitive data being sent (even after redaction)?
   Which services receive the most sensitive context?
3. PROMPT QUALITY — are prompts specific and effective, or vague? Any anti-patterns?
4. SECURITY OBSERVATIONS — anything noteworthy about what context is being shared with AI tools?
5. RECOMMENDATIONS — concrete actions to improve workflow, reduce sensitive data exposure,
   or get better results from AI tools.

Keep the analysis practical and specific to what you actually observe in the data below.
Where useful, quote specific prompt excerpts to support your points.

%s
EXPORT METADATA
Generated : %s
Range     : %s → %s
Total     : %d prompts (%d blocked, %d redacted)
%s

`,
		fromStr, toStr, len(prompts), blocked, redacted,
		strings.Repeat("=", 72),
		time.Now().Format("2006-01-02 15:04:05"),
		fromStr, toStr,
		len(prompts), blocked, redacted,
		strings.Repeat("=", 72),
	)

	for i, p := range prompts {
		var text string
		switch {
		case p.Status == store.StatusBlocked:
			// Never export raw content of blocked prompts — it contains the sensitive value that triggered the block.
			rules := make([]string, 0, len(p.Matches))
			for _, m := range p.Matches {
				rules = append(rules, m.RuleName)
			}
			text = fmt.Sprintf("[blocked — content withheld. Rules matched: %s]", strings.Join(rules, ", "))
		case p.RedactedPrompt != "":
			text = p.RedactedPrompt
		default:
			text = p.Prompt
		}
		fmt.Fprintf(w, "[%d] %s | %s | %s\n%s\n\n",
			i+1,
			p.Timestamp.Format("2006-01-02 15:04"),
			p.Host,
			string(p.Status),
			text,
		)
	}
}

// apiScan is a dry-run rule tester — runs the inspector against submitted text
// without forwarding anything to an LLM.
func apiScan(w http.ResponseWriter, r *http.Request, eng *inspector.Engine) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Text == "" {
		http.Error(w, "invalid JSON or empty text", http.StatusBadRequest)
		return
	}

	inspectResult := eng.Inspect(body.Text)
	redacted, trackMatches := eng.RedactText(body.Text)

	type matchOut struct {
		RuleID   string `json:"rule_id"`
		RuleName string `json:"rule_name"`
		Severity string `json:"severity"`
		Mode     string `json:"mode"`
		Snippet  string `json:"snippet"`
	}
	allMatches := []matchOut{}
	for _, m := range inspectResult.Matches {
		allMatches = append(allMatches, matchOut{m.RuleID, m.RuleName, m.Severity, m.Mode, m.Snippet})
	}
	for _, m := range trackMatches {
		allMatches = append(allMatches, matchOut{m.RuleID, m.RuleName, m.Severity, m.Mode, m.Snippet})
	}

	status := "clean"
	if inspectResult.Blocked {
		status = "blocked"
	} else if len(trackMatches) > 0 {
		status = "redacted"
	}

	jsonResponse(w, map[string]any{
		"status":   status,
		"matches":  allMatches,
		"redacted": redacted,
		"original": body.Text,
	})
}

func jsonResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ── Dashboard HTML ────────────────────────────────────────────────────────────

var dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Prompt Guard</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<script>
  var t = localStorage.getItem('pg-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', t);
</script>
<style>
  :root { color-scheme: dark; }
  [data-theme=dark] {
    --bg-base:    #0b0d10;
    --bg-surface: #111318;
    --bg-raised:  #181c23;
    --bg-input:   #0f1115;
    --border:     #242830;
    --border-sub: #1c2028;
    --text-1:     #e2e8f3;
    --text-2:     #8b96ab;
    --text-3:     #4a5468;
    --accent:     #3b82f6;
    --accent-dim: rgba(59,130,246,.12);
    --danger:     #ef4444;
    --danger-dim: rgba(239,68,68,.10);
    --warning:    #f59e0b;
    --warning-dim:rgba(245,158,11,.10);
    --success:    #10b981;
    --success-dim:rgba(16,185,129,.10);
    --purple:     #a78bfa;
    --purple-dim: rgba(167,139,250,.10);
    --blocked-bg: rgba(239,68,68,.06);
    --redacted-bg:rgba(167,139,250,.06);
    --flagged-bg: rgba(245,158,11,.05);
  }
  [data-theme=light] {
    --bg-base:    #f1f3f7;
    --bg-surface: #ffffff;
    --bg-raised:  #f8f9fc;
    --bg-input:   #f4f5f8;
    --border:     #e2e6ef;
    --border-sub: #eceef4;
    --text-1:     #0f172a;
    --text-2:     #475569;
    --text-3:     #94a3b8;
    --accent:     #2563eb;
    --accent-dim: rgba(37,99,235,.08);
    --danger:     #dc2626;
    --danger-dim: rgba(220,38,38,.07);
    --warning:    #d97706;
    --warning-dim:rgba(217,119,6,.07);
    --success:    #059669;
    --success-dim:rgba(5,150,105,.07);
    --purple:     #7c3aed;
    --purple-dim: rgba(124,58,237,.07);
    --blocked-bg: rgba(220,38,38,.05);
    --redacted-bg:rgba(124,58,237,.05);
    --flagged-bg: rgba(217,119,6,.04);
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Inter', system-ui, sans-serif; background: var(--bg-base); color: var(--text-1); font-size: 14px; min-height: 100vh; }

  /* ── Header ────────────────────────────────────── */
  .hd { display: flex; align-items: center; gap: 10px; padding: 0 24px; height: 54px;
        background: var(--bg-surface); border-bottom: 1px solid var(--border);
        position: sticky; top: 0; z-index: 100;
        /* Subtle backdrop blur adds depth without full opacity */
        backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); }
  .hd-logo { display: flex; align-items: center; gap: 9px; }
  .hd-shield { width: 26px; height: 26px; flex-shrink: 0; }
  /* Product name: "Prompt" in default text, "Guard" in accent — reversed from original
     so the differentiating word is accented, matching Linear/Vercel conventions */
  .hd-name { font-weight: 700; font-size: 15px; letter-spacing: -.4px; }
  .hd-name em { color: var(--accent); font-style: normal; }
  .hd-sep { width: 1px; height: 16px; background: var(--border); margin: 0 2px; }
  /* PROXY badge: pill shape, slightly more padding, matches Datadog env badges */
  .hd-badge { background: var(--accent-dim); color: var(--accent); border: 1px solid rgba(59,130,246,.25);
              border-radius: 20px; padding: 2px 9px; font-size: 10px; font-weight: 700; letter-spacing: .6px;
              text-transform: uppercase; }
  /* Clock: subtler, right-aligned after spacer */
  .hd-meta { color: var(--text-3); font-size: 11.5px; font-variant-numeric: tabular-nums; letter-spacing: .2px; }
  /* Live indicator: add "LIVE" text for clarity, pulse stays */
  .hd-live { display: flex; align-items: center; gap: 6px; color: var(--success); font-size: 11px; font-weight: 700;
             letter-spacing: .4px; text-transform: uppercase; }
  .hd-live::before { content:''; width:7px; height:7px; border-radius:50%; background:var(--success);
                     box-shadow:0 0 0 0 var(--success); animation:pulse 2s infinite; flex-shrink:0; }
  @keyframes pulse { 0%{box-shadow:0 0 0 0 rgba(16,185,129,.6)} 70%{box-shadow:0 0 0 8px rgba(16,185,129,0)} 100%{box-shadow:0 0 0 0 rgba(16,185,129,0)} }
  .hd-spacer { flex: 1; }
  .agent-mode-btn { display:flex; align-items:center; gap:5px; border:1px solid var(--border);
                    background:transparent; color:var(--text-2); border-radius:7px;
                    height:32px; padding:0 10px; font-size:10px; font-weight:600; letter-spacing:.4px;
                    cursor:pointer; text-transform:uppercase; transition:all .15s; flex-shrink:0; font-family:inherit; }
  .agent-mode-btn:hover { background:var(--bg-raised); border-color:var(--text-3); color:var(--text-1); }
  .agent-mode-state { font-size:10px; font-weight:700; color:var(--text-3); }
  .agent-mode-btn.is-on { background:rgba(245,158,11,.12); border-color:rgba(245,158,11,.4); color:#f59e0b; }
  .agent-mode-btn.is-on .agent-mode-state { color:#f59e0b; }
  /* Icon buttons: proper SVG icons instead of emoji, square with defined size */
  .ri-wrap { display:flex;align-items:center;gap:4px;border:1px solid var(--border);border-radius:7px;padding:2px 4px;height:30px; }
  .ri-opt { background:transparent;border:none;color:var(--text-3);font-size:11px;padding:2px 6px;border-radius:5px;cursor:pointer;font-family:inherit; }
  .ri-opt:hover { background:var(--bg-raised);color:var(--text-1); }
  .ri-opt-active { background:var(--bg-raised);color:var(--text-1);font-weight:600; }
  .ri-sep { width:1px;background:var(--border);height:14px;margin:0 2px; }
  .ri-refresh-btn { background:transparent;border:none;color:var(--text-2);cursor:pointer;padding:3px 5px;border-radius:5px;display:flex;align-items:center; }
  .ri-refresh-btn:hover { background:var(--bg-raised);color:var(--text-1); }
  .ri-refresh-btn svg { width:13px;height:13px;stroke:currentColor;stroke-width:2;fill:none; }
  #latency-toggle:hover { background:rgba(255,255,255,0.04); }
  .icon-btn { border: 1px solid var(--border); background: transparent; color: var(--text-2);
              border-radius: 7px; width: 32px; height: 32px; cursor: pointer; font-family: inherit;
              display: flex; align-items: center; justify-content: center; flex-shrink: 0;
              transition: background .15s, border-color .15s, color .15s; }
  .icon-btn:hover { background: var(--bg-raised); border-color: var(--text-3); color: var(--text-1); }
  .icon-btn svg { width: 15px; height: 15px; fill: none; stroke: currentColor; stroke-width: 1.75;
                  stroke-linecap: round; stroke-linejoin: round; pointer-events: none; }

  /* ── Layout ────────────────────────────────────── */
  .pg-main { padding: 18px 24px; max-width: 100%; margin: 0 auto; }
  .pg-cols { display: grid; grid-template-columns: 1fr 360px; gap: 16px; align-items: start; transition: grid-template-columns .2s ease; }
  body.rules-collapsed .pg-cols { grid-template-columns: 1fr 28px; }
  @media(max-width:880px) { .pg-cols { grid-template-columns: 1fr; } }

  /* ── Rules panel collapse ───────────────────────── */
  .rules-panel-wrap { position: sticky; top: 52px; }
  .rules-toggle-btn {
    background: none; border: none; cursor: pointer;
    font-size: 14px; color: var(--text-3); padding: 0 4px; line-height: 1;
    margin-left: auto;
  }
  .rules-toggle-btn:hover { color: var(--text-1); }
  .rules-panel-inner { overflow: hidden; transition: opacity .15s; }
  body.rules-collapsed .rules-panel-inner { opacity: 0; pointer-events: none; display: none; }
  /* Collapsed strip: arrow at top, vertical label below — no overlap */
  .rules-collapsed-strip {
    display: none; flex-direction: column; align-items: center;
    cursor: pointer; padding-top: 8px; gap: 8px;
  }
  .rules-collapsed-strip:hover .rules-collapsed-arrow { color: var(--text-1); }
  .rules-collapsed-arrow {
    font-size: 14px; color: var(--text-3); line-height: 1;
  }
  .rules-collapsed-label {
    writing-mode: vertical-rl; transform: rotate(180deg);
    font-size: 10.5px; font-weight: 700; letter-spacing: .6px; text-transform: uppercase;
    color: var(--text-3); white-space: nowrap;
  }
  body.rules-collapsed .rules-collapsed-strip { display: flex; }

  /* ── Metric tiles ──────────────────────────────── */
  /* 7-column grid; last 2 (telemetry, top-host) are utility/metadata and narrower visually */
  .tiles { display: grid; grid-template-columns: repeat(8, 1fr); gap: 10px; margin-bottom: 18px; }
  @media(max-width:1100px) { .tiles { grid-template-columns: repeat(4, 1fr); } }
  @media(max-width:640px)  { .tiles { grid-template-columns: repeat(2, 1fr); } }

  .tile { background: var(--bg-surface); border: 1px solid var(--border); border-radius: 10px;
          padding: 14px 16px 13px; position: relative; overflow: hidden;
          transition: border-color .2s; }
  /* Model latency cards — accent bar colour */
  .tile-model::before { background: linear-gradient(90deg,#06b6d4 0%,transparent 85%); }
  /* Top accent bar — 3px for the five primary metrics */
  .tile::before { content:''; position:absolute; top:0;left:0;right:0; height:3px; border-radius:10px 10px 0 0; }
  .tile-total::before   { background: linear-gradient(90deg,var(--accent) 0%,transparent 85%); }
  .tile-clean::before   { background: linear-gradient(90deg,var(--success) 0%,transparent 85%); }
  .tile-flagged::before { background: linear-gradient(90deg,var(--warning) 0%,transparent 85%); }
  .tile-redacted::before{ background: linear-gradient(90deg,var(--purple) 0%,transparent 85%); }
  .tile-blocked::before { background: linear-gradient(90deg,var(--danger) 0%,transparent 85%); }
  /* Telemetry gets a distinct teal accent — it is security-relevant, not neutral */
  .tile-telemetry::before { background: linear-gradient(90deg,#06b6d4 0%,transparent 85%); }
  /* Top host — grey, it is metadata not a metric */
  .tile-tophost::before { background: linear-gradient(90deg,var(--border) 0%,transparent 60%); }

  /* CRITICAL STATE: when blocked/flagged tile has a non-zero value, glow the border.
     Applied by JS via .tile--alert class. */
  .tile--alert { border-color: rgba(239,68,68,.35); box-shadow: 0 0 0 1px rgba(239,68,68,.12), inset 0 0 20px rgba(239,68,68,.04); }
  .tile--alert .tile-lbl { color: rgba(239,68,68,.7); }

  .tile-lbl { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: .7px;
              color: var(--text-3); margin-bottom: 8px; }
  /* Primary metrics get a larger, bolder number — these drive decisions */
  .tile-val { font-size: 26px; font-weight: 700; line-height: 1; letter-spacing: -.5px;
              font-variant-numeric: tabular-nums; }
  .tile-val.c-total   { color: var(--text-1); }
  .tile-val.c-clean   { color: var(--success); }
  .tile-val.c-flagged { color: var(--warning); }
  .tile-val.c-redacted{ color: var(--purple); }
  .tile-val.c-blocked { color: var(--danger); }
  /* Telemetry value: smaller weight — it is a secondary signal */
  .tile-val.c-telemetry { color: #06b6d4; font-size: 22px; }
  .tile-sub { font-size: 11px; color: var(--text-3); margin-top: 5px; letter-spacing: .1px; }
  /* Top host tile: compact hostname display */
  .tile-host-val { font-size: 11.5px; font-weight: 600; margin-top: 4px;
                   overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text-1); }

  /* ── Panel ─────────────────────────────────────── */
  .panel { background: var(--bg-surface); border: 1px solid var(--border); border-radius: 10px;
           overflow: hidden; margin-bottom: 14px; }
  .panel-hd { display: flex; align-items: center; gap: 8px; padding: 12px 16px;
              border-bottom: 1px solid var(--border); }
  /* Panel title: slightly larger than before, matches Grafana panel headers */
  .panel-title { font-weight: 600; font-size: 13px; letter-spacing: -.1px; }
  /* Count badge: pill, matches Linear's issue count chips */
  .panel-count { background: var(--bg-raised); border: 1px solid var(--border); border-radius: 20px;
                 padding: 1px 9px; font-size: 11px; color: var(--text-2); font-weight: 600;
                 font-variant-numeric: tabular-nums; }

  /* ── Search ────────────────────────────────────── */
  .search-wrap { margin-left: auto; flex-shrink: 1; min-width: 0; }
  .search-input { background: var(--bg-input); border: 1px solid var(--border); border-radius: 6px;
                  color: var(--text-1); font-family: inherit; font-size: 12px; padding: 4px 10px;
                  width: 220px; outline: none; transition: border-color .15s; }
  .search-input::placeholder { color: var(--text-3); }
  .search-input:focus { border-color: var(--accent); }
  /* ── Filter tabs ───────────────────────────────── */
  /* Segmented control pattern used by Linear and Vercel — sits on bg-raised, active is surface+shadow */
  .ftabs { display: flex; gap: 2px; margin-left: 8px; background: var(--bg-raised); border: 1px solid var(--border);
           border-radius: 7px; padding: 3px; flex-shrink: 0; }
  .ftab { border: none; background: transparent; color: var(--text-3); border-radius: 5px;
          padding: 4px 11px; font-size: 11px; font-weight: 600; cursor: pointer; font-family: inherit;
          letter-spacing: .15px; transition: color .12s, background .12s; white-space: nowrap; }
  .ftab:hover { color: var(--text-1); background: rgba(255,255,255,.04); }
  .ftab.active { background: var(--bg-surface); color: var(--text-1);
                 box-shadow: 0 1px 2px rgba(0,0,0,.18), 0 0 0 0.5px rgba(0,0,0,.08); }

  /* ── Scrollbars ─────────────────────────────────── */
  ::-webkit-scrollbar { width: 5px; height: 5px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 99px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--text-3); }

  /* ── Table ─────────────────────────────────────── */
  .tbl-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; min-height: 320px; }
  .pg-tbl { width: 100%; border-collapse: collapse; table-layout: fixed; }
  .pg-tbl th:nth-child(1) { width: 110px; }  /* Time */
  .pg-tbl th:nth-child(2) { width: 85px; }   /* Status */
  .pg-tbl th:nth-child(3) { width: 190px; }  /* Host */
  .pg-tbl th:nth-child(4) { width: 110px; }  /* Path */
  .pg-tbl th:nth-child(5) { width: 140px; }  /* Rules Hit */
  .pg-tbl th:nth-child(6) { width: 65px; }   /* Latency */
  .pg-tbl th:nth-child(7) { width: 120px; }  /* Tokens in/out */
  .pg-tbl th:nth-child(8) { width: 44px; text-align:center; }  /* CTX */
  .pg-tbl th:nth-child(9) { width: 85px; }   /* Session */
  .pg-tbl th:nth-child(10){ width: 160px; }  /* Client */
  .pg-tbl th:nth-child(11){ width: 140px; }  /* Model */
  /* Column headers: tighter letter-spacing, standard Datadog table header style */
  .pg-tbl th { font-size: 10.5px; font-weight: 700; text-transform: uppercase; letter-spacing: .6px;
               color: var(--text-3); padding: 8px 16px; border-bottom: 1px solid var(--border);
               background: var(--bg-raised); white-space: nowrap; text-align: left; }
  /* Data rows: taller for breathing room — 11px vertical padding is industry standard for dense tables */
  .pg-tbl td { padding: 11px 16px; border-bottom: 1px solid var(--border-sub); color: var(--text-1); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
               vertical-align: middle; white-space: nowrap; font-size: 13px; }
  .pg-tbl tr:last-child td { border-bottom: none; }
  .pg-tbl tbody tr { cursor: pointer; transition: background .1s; }
  /* Hover: slightly brighter bg + left accent line for clear row selection affordance */
  .pg-tbl tbody tr:hover td { background: var(--bg-raised); }
  .pg-tbl tbody tr:hover td:first-child { box-shadow: inset 2px 0 0 var(--accent); }
  .pg-tbl .muted { color: var(--text-3); }
  /* Monospace: slightly larger than before, legible at 14px base */
  .pg-tbl .mono  { font-family: 'SF Mono','Fira Code',ui-monospace,Menlo,monospace; font-size: 12px; }
  /* Empty state: more breathing room, actionable message */
  .pg-tbl .td-r    { text-align: left; }
  .pg-tbl .td-host { font-weight: 600; }
  .pg-tbl .td-path { font-family: 'SF Mono','Fira Code',ui-monospace,Menlo,monospace; font-size: 12px; color: var(--text-3); }
  .pg-tbl .empty td { color: var(--text-3); text-align: center; padding: 56px 36px; cursor: default;
                       font-size: 13px; line-height: 1.6; }
  /* Pagination bar */
  .pagination { display:flex; align-items:center; gap:6px; padding:10px 16px;
                border-top:1px solid var(--border); font-size:12px; color:var(--text-2); }
  .pagination .pg-info { flex:1; font-size: 12px; font-variant-numeric: tabular-nums; }
  .pg-btn { background:var(--bg-raised); border:1px solid var(--border); color:var(--text-2);
            padding:4px 12px; border-radius:6px; cursor:pointer; font-size:12px; font-family:inherit;
            transition: border-color .15s, color .15s; }
  .pg-btn:disabled { opacity:.3; cursor:default; }
  .pg-btn:not(:disabled):hover { border-color:var(--accent); color:var(--text-1); }
  .pg-select { background:var(--bg-raised); border:1px solid var(--border); color:var(--text-2);
               padding:4px 7px; border-radius:6px; font-size:12px; cursor:pointer; font-family:inherit; }
  /* Row tinting: slightly more opaque than before for better legibility on light theme */
  .pg-tbl tr.row-blocked  td { background: var(--blocked-bg); }
  .pg-tbl tr.row-flagged  td { background: var(--flagged-bg); }
  .pg-tbl tr.row-redacted td { background: var(--redacted-bg); }

  /* ── Detail row ────────────────────────────────── */
  /* ── Detail row ────────────────────────────────── */
  /* Left-inset border connects visually to the expanded row above */
  .detail-row td { background: var(--bg-input) !important; padding: 0 !important;
                   white-space: normal !important; cursor: default !important;
                   border-left: 3px solid var(--accent) !important; }
  .detail-inner { padding: 16px 20px; display: grid; gap: 14px; }
  .detail-section-lbl { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: .7px;
                        color: var(--text-3); margin-bottom: 6px; }
  .detail-section-lbl.lbl-purple { color: var(--purple); }
  /* Prompt text: proportional font (Inter) for readable prose, not monospace.
     Monospace is reserved for the matched snippet (the actual sensitive fragment). */
  .detail-pre { font-family: 'Inter', system-ui, sans-serif; font-size: 13px; color: var(--text-2);
                background: var(--bg-base); border: 1px solid var(--border); border-radius: 7px;
                padding: 12px 14px; white-space: pre-wrap; word-break: break-word;
                max-height: 180px; overflow-y: auto; line-height: 1.7; }
  /* Banner: icon-forward layout, slightly more padding */
  .banner { border-radius: 7px; padding: 9px 14px; font-size: 12.5px; font-weight: 600;
            display: flex; align-items: center; gap: 9px; }
  .banner-blocked  { background: var(--danger-dim);  border: 1px solid rgba(239,68,68,.3);   color: var(--danger);  }
  .banner-redacted { background: var(--purple-dim);  border: 1px solid rgba(167,139,250,.3); color: var(--purple); }
  .detail-wrap { padding: 16px 20px; display: grid; gap: 14px; }
  /* Match list */
  .match-list { display: flex; flex-direction: column; gap: 6px; }
  .match-item { display: flex; align-items: flex-start; gap: 12px; background: var(--bg-surface);
                border: 1px solid var(--border); border-radius: 7px; padding: 10px 12px; }
  .match-meta { display: flex; flex-direction: column; gap: 5px; min-width: 80px; flex-shrink: 0; }
  /* Snippets stay monospace — these are the actual matched credential fragments */
  .match-snippet { font-family: 'SF Mono','Fira Code',ui-monospace,Menlo,monospace; font-size: 11px;
                   color: var(--text-2); flex: 1; word-break: break-all; line-height: 1.55; }

  /* ── Tags ──────────────────────────────────────── */
  /* Base tag: increased padding and font-size — status tags are primary data, not footnotes */
  .tag { display: inline-flex; align-items: center; border-radius: 5px; padding: 3px 8px; font-size: 10.5px;
         font-weight: 700; letter-spacing: .4px; text-transform: uppercase; white-space: nowrap; }
  /* Severity tags (used in match details) */
  .tag-high    { background: var(--danger-dim);  color: var(--danger);  border: 1px solid rgba(239,68,68,.3); }
  .tag-medium  { background: var(--warning-dim); color: var(--warning); border: 1px solid rgba(245,158,11,.3); }
  .tag-low     { background: var(--accent-dim);  color: var(--accent);  border: 1px solid rgba(59,130,246,.25); }
  /* Status tags — blocked is the most critical: slightly wider padding, stronger border */
  .tag-blocked  { background: var(--danger-dim);  color: var(--danger);  border: 1px solid rgba(239,68,68,.4);
                  padding: 3px 9px; }
  .tag-flagged  { background: var(--warning-dim); color: var(--warning); border: 1px solid rgba(245,158,11,.35); }
  .tag-redacted { background: var(--purple-dim);  color: var(--purple);  border: 1px solid rgba(167,139,250,.35); }
  .tag-clean    { background: var(--success-dim); color: var(--success); border: 1px solid rgba(16,185,129,.3); }
  /* Telemetry: distinct teal to match its tile accent */
  .tag-telemetry { background: rgba(6,182,212,.1); color: #06b6d4; border: 1px solid rgba(6,182,212,.25); }
  /* Mode mini-tags used in rule match details */
  .mm { font-size: 10px; font-weight: 700; text-transform: uppercase; padding: 2px 6px; border-radius: 4px;
        letter-spacing: .3px; }
  .mm-block { background: var(--danger-dim);  color: var(--danger);  border: 1px solid rgba(239,68,68,.2); }
  .mm-track { background: var(--accent-dim);  color: var(--accent);  border: 1px solid rgba(59,130,246,.2); }
  .mm-redact { background: var(--purple-dim); color: var(--purple);  border: 1px solid rgba(167,139,250,.2); }

  /* ── Rule cards ────────────────────────────────── */
  /* Card layout reworked: severity+control on one row, name+desc below.
     This puts the actionable control (Track/Block) beside the severity signal,
     so operator can scan severity → decide mode without vertical jumping. */
  .rules-search-wrap { padding: 8px 10px 6px; border-bottom: 1px solid var(--border-sub); }
  .rules-search-input { width: 100%; box-sizing: border-box; background: var(--bg-input);
    border: 1px solid var(--border); border-radius: 6px; padding: 5px 9px;
    font-size: 12px; color: var(--text-1); font-family: inherit; outline: none; }
  .rules-search-input::placeholder { color: var(--text-3); }
  .rules-search-input:focus { border-color: var(--accent); }
  .rules-group-hd { padding: 5px 14px 4px; font-size: 10px; font-weight: 600; letter-spacing: .06em; text-transform: uppercase; color: var(--text-3); background: var(--bg-raised); border-bottom: 1px solid var(--border-sub); position: sticky; top: 0; z-index: 1; }
  .rules-group-hd.sev-hd-high   { color: var(--danger); }
  .rules-group-hd.sev-hd-medium { color: var(--warning); }
  .rules-group-hd.sev-hd-low    { color: var(--accent); }
  .rule-card { padding: 9px 12px 9px 13px; border-bottom: 1px solid var(--border-sub);
               display: flex; flex-direction: column; gap: 6px;
               border-left: 3px solid transparent; transition: background .15s; }
  .rule-card:last-child { border-bottom: none; }
  .rule-card.sev-high   { border-left-color: var(--danger); }
  .rule-card.sev-medium { border-left-color: var(--warning); }
  .rule-card.sev-low    { border-left-color: var(--accent); }
  .rule-card:hover { background: var(--bg-raised); }
  /* Row 1: rule name (left) + segmented control (right) — primary action always visible */
  .rule-top { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
  .rule-info { min-width: 0; flex: 1; }
  .rule-name { font-weight: 600; font-size: 12px; line-height: 1.35;
               display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical;
               overflow: hidden; }
  /* Row 2: description — capped at 2 lines, subordinate */
  .rule-desc { color: var(--text-3); font-size: 11px; line-height: 1.4;
               display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical;
               overflow: hidden; }
  .rule-foot { display: flex; align-items: center; gap: 6px; }

  /* Segmented control — Track / Block
     Increased padding for easier tap/click targets, rounded outer corners */
  .seg { display: flex; border: 1px solid var(--border); border-radius: 5px; overflow: hidden;
         flex-shrink: 0; background: var(--bg-raised); }
  .seg-btn { border: none; background: transparent; color: var(--text-3); padding: 3px 7px;
             font-size: 10px; font-weight: 700; cursor: pointer; font-family: inherit;
             letter-spacing: .3px; transition: background .15s, color .15s; text-transform: uppercase; }
  .seg-btn + .seg-btn { border-left: 1px solid var(--border); }
  .seg-btn:hover:not(.seg-active-track):not(.seg-active-block) {
    color: var(--text-1); background: rgba(255,255,255,.04); }
  .seg-btn.seg-active-track  { background: var(--accent-dim);  color: var(--accent);  }
  .seg-btn.seg-active-block  { background: var(--danger-dim);  color: var(--danger);  }
  .seg-btn:disabled { opacity: .45; cursor: wait; }
</style>
</head>
<body>

<header class="hd">
  <div class="hd-logo">
    <a href="https://github.com/chaudharydeepak/prompt-guard" target="_blank" rel="noopener" style="display:flex;align-items:center;gap:9px;text-decoration:none;color:inherit;">
    <img src="/favicon.svg" class="hd-shield" alt="Prompt Guard">
    <div class="hd-name">Prompt<em>Guard</em></div>
    </a>
  </div>
  <div class="hd-sep"></div>
  <div class="hd-badge">PROXY</div>
  <div class="hd-sep"></div>
  <div class="hd-live">Live</div>
  <div class="hd-sep"></div>
  <div class="hd-meta" id="meta">connecting…</div>
  <div class="hd-spacer"></div>
  <!-- Refresh interval control -->
  <div class="ri-wrap" id="ri-wrap">
    <button class="ri-refresh-btn" onclick="manualRefresh()" title="Refresh now">
      <svg viewBox="0 0 24 24"><path d="M4 4v5h5M20 20v-5h-5"/><path d="M4.07 15a8 8 0 1 0 .29-4.88L4 9"/></svg>
    </button>
    <div class="ri-sep"></div>
  </div>
  <!-- Download icon (Heroicons outline) -->
  <button class="icon-btn" onclick="toggleExport()" title="Export prompts" id="export-btn">
    <svg viewBox="0 0 24 24"><path d="M12 4v12m0 0-4-4m4 4 4-4M4 20h16"/></svg>
  </button>
  <!-- Rule tester -->
  <button class="icon-btn" onclick="toggleTester()" title="Rule Tester — test text against rules without sending to any LLM" id="tester-btn">
    <svg viewBox="0 0 24 24"><path d="M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 3v18m0 0h10a2 2 0 0 0 2-2v-4M9 21H5a2 2 0 0 1-2-2v-4m0 0h18"/></svg>
  </button>
  <!-- Agent mode toggle -->
  <button onclick="toggleAgentMode()" id="agent-btn" class="agent-mode-btn"
    title="Agent Mode: when ON, all rules switch to redact — sensitive data is masked before reaching the AI but requests are never blocked. Use when running long-lived agents that must not be interrupted.">
    <span id="agent-btn-label">Agent Mode</span>
    <span id="agent-btn-state" class="agent-mode-state">OFF</span>
  </button>
  <!-- Trash / clear all icon -->
  <button class="icon-btn" onclick="clearAllPrompts()" title="Clear all prompts" id="clear-btn">
    <svg viewBox="0 0 24 24"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/></svg>
  </button>
  <!-- Sun/moon icon swapped by JS -->
  <button class="icon-btn" onclick="toggleTheme()" title="Toggle theme" id="theme-btn">
    <svg viewBox="0 0 24 24" id="theme-icon-sun"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>
    <svg viewBox="0 0 24 24" id="theme-icon-moon" style="display:none"><path d="M21 12.79A9 9 0 1 1 11.21 3a7 7 0 0 0 9.79 9.79z"/></svg>
  </button>
</header>

<div id="export-panel" style="display:none;position:fixed;top:52px;right:12px;z-index:100;
  background:var(--bg-surface);border:1px solid var(--border);border-radius:10px;
  padding:16px;width:280px;box-shadow:0 8px 24px rgba(0,0,0,.3);">
  <div style="font-weight:600;font-size:13px;margin-bottom:12px">Export for LLM analysis</div>
  <div style="display:flex;flex-direction:column;gap:6px;margin-bottom:12px">
    <button class="ftab" onclick="doExport('today')">Today</button>
    <button class="ftab" onclick="doExport('7d')">Last 7 days</button>
    <button class="ftab" onclick="doExport('30d')">Last 30 days</button>
    <button class="ftab" onclick="doExport('all')">All time</button>
  </div>
  <div style="font-size:11px;color:var(--text-3);margin-bottom:6px">Custom range</div>
  <div style="display:flex;gap:6px;align-items:center;margin-bottom:10px">
    <input type="date" id="exp-from" style="flex:1;background:var(--bg-input);border:1px solid var(--border);
      border-radius:5px;padding:4px 7px;color:var(--text-1);font-size:11.5px">
    <span style="color:var(--text-3);font-size:11px">→</span>
    <input type="date" id="exp-to" style="flex:1;background:var(--bg-input);border:1px solid var(--border);
      border-radius:5px;padding:4px 7px;color:var(--text-1);font-size:11.5px">
  </div>
  <button class="ftab" style="width:100%" onclick="doExport('custom')">Download</button>
  <div style="margin-top:10px;font-size:10.5px;color:var(--text-3);line-height:1.5">
    Plain text file. Paste into any LLM to analyse your usage patterns.
  </div>
</div>

<!-- Rule Tester backdrop -->
<div id="tester-backdrop" onclick="toggleTester()" style="display:none;position:fixed;inset:0;z-index:199;background:rgba(0,0,0,.45)"></div>

<!-- Rule Tester modal -->
<div id="tester-panel" style="display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);
  z-index:200;background:var(--bg-surface);border:1px solid var(--border);border-radius:12px;
  padding:28px 32px;width:680px;max-width:calc(100vw - 48px);box-shadow:0 16px 48px rgba(0,0,0,.45);">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
    <div style="font-weight:700;font-size:15px">Rule Tester</div>
    <button onclick="toggleTester()" style="background:transparent;border:none;color:var(--text-3);
      font-size:18px;cursor:pointer;line-height:1;padding:2px 6px">&times;</button>
  </div>
  <div style="font-size:12px;color:var(--text-3);margin-bottom:16px">Paste any text — rules fire locally, nothing is forwarded to an LLM. Note: this tests raw text only; real clients may wrap prompts in XML, inject file contents via tool calls, or structure messages differently — those scenarios won't be captured here.</div>
  <textarea id="tester-input" placeholder="Paste a prompt to test rules against it…"
    style="width:100%;box-sizing:border-box;height:200px;resize:vertical;
    background:var(--bg-input);border:1px solid var(--border);border-radius:6px;
    color:var(--text-1);font-family:inherit;font-size:13px;padding:10px 12px;
    line-height:1.6;outline:none"
    onkeydown="if(event.metaKey&&event.key==='Enter')runScan()"></textarea>
  <div style="display:flex;justify-content:flex-end;margin-top:10px;gap:8px">
    <button onclick="clearTester()" style="background:transparent;border:1px solid var(--border);
      color:var(--text-3);border-radius:6px;padding:6px 18px;font-size:13px;cursor:pointer">Clear</button>
    <button onclick="runScan()" id="scan-btn" style="background:#3b82f6;border:none;
      color:#fff;border-radius:6px;padding:6px 22px;font-size:13px;cursor:pointer;font-weight:500">Scan</button>
  </div>
  <div id="tester-results" style="margin-top:18px;display:none">
    <div style="border-top:1px solid var(--border);padding-top:14px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">
        <span style="font-size:12px;font-weight:600;color:var(--text-2)">Result:</span>
        <span id="tester-status-badge" style="font-size:11.5px;font-weight:600;padding:3px 10px;border-radius:4px"></span>
      </div>
      <div id="tester-matches" style="display:none;margin-bottom:12px"></div>
      <div id="tester-redacted-wrap" style="display:none">
        <div style="font-size:12px;font-weight:600;color:var(--text-2);margin-bottom:6px">Redacted output:</div>
        <pre id="tester-redacted-text" style="background:var(--bg-raised);border:1px solid var(--border);
          border-radius:6px;padding:10px 12px;font-size:12px;color:var(--text-2);
          white-space:pre-wrap;word-break:break-all;margin:0;max-height:220px;overflow:auto"></pre>
      </div>
    </div>
  </div>
</div>

<main class="pg-main">

  <div class="tiles">
    <div class="tile tile-total">
      <div class="tile-lbl">Total</div>
      <div class="tile-val c-total" id="tile-total">—</div>
      <div class="tile-sub">intercepted</div>
    </div>
    <div class="tile tile-clean">
      <div class="tile-lbl">Clean</div>
      <div class="tile-val c-clean" id="tile-clean">—</div>
      <div class="tile-sub">no rules fired</div>
    </div>
    <div class="tile tile-flagged">
      <div class="tile-lbl">Flagged</div>
      <div class="tile-val c-flagged" id="tile-flagged">—</div>
      <div class="tile-sub">tracked · forwarded</div>
    </div>
    <div class="tile tile-redacted">
      <div class="tile-lbl">Redacted</div>
      <div class="tile-val c-redacted" id="tile-redacted">—</div>
      <div class="tile-sub">sanitised · forwarded</div>
    </div>
    <div class="tile tile-blocked">
      <div class="tile-lbl">Blocked</div>
      <div class="tile-val c-blocked" id="tile-blocked">—</div>
      <div class="tile-sub">stopped at proxy</div>
    </div>
    <div class="tile tile-telemetry">
      <div class="tile-lbl">Telemetry</div>
      <div class="tile-val c-telemetry" id="tile-telemetry">—</div>
      <div class="tile-sub">analytics calls</div>
    </div>
    <div class="tile tile-tophost">
      <div class="tile-lbl">Top Host</div>
      <div class="tile-host-val" id="tile-host">—</div>
      <div class="tile-sub">most flagged</div>
    </div>
    <div class="tile tile-tokens">
      <div class="tile-lbl">Context In</div>
      <div class="tile-val" id="tile-tokens">—</div>
      <div class="tile-sub">total input tokens</div>
    </div>
  </div>

  <!-- Model latency row (collapsible) -->
  <div id="model-latency-row" style="display:none;margin-bottom:18px">
    <div id="latency-panel" style="background:var(--bg-surface);border-radius:6px;box-shadow:0 0 0 1px var(--border),inset 3px 0 0 #4f8ef7">
      <button id="latency-toggle" onclick="toggleLatencyPanel()" aria-expanded="false" aria-controls="latency-table-wrap" style="width:100%;display:flex;align-items:center;gap:8px;padding:9px 14px;background:transparent;border:none;cursor:pointer;text-align:left;color:var(--text-2);font-size:12px;font-weight:600;letter-spacing:0.04em;text-transform:uppercase;user-select:none">
        <span id="latency-chevron" style="display:inline-block;font-size:10px;transition:transform 0.15s ease-out;transform:rotate(0deg);color:var(--text-3);line-height:1">&#9654;</span>
        <span>Model Latency</span>
        <span id="latency-summary" style="margin-left:auto;font-size:11px;font-weight:400;color:var(--text-3);letter-spacing:0;text-transform:none"></span>
      </button>
      <div id="latency-table-wrap" style="height:0;overflow:hidden">
        <!-- <div style="border-top:1px solid var(--border);padding:4px 0 4px"> -->
          <div id="model-latency-body" style="max-height:260px;overflow-y:auto;overflow-x:hidden"></div>
        <!-- </div> -->
      </div>
    </div>
  </div>

  <div class="pg-cols">
    <!-- Prompts table -->
    <div>
      <div class="panel">
        <div class="panel-hd">
          <span class="panel-title">Prompts</span>
          <span class="panel-count" id="prompt-count">0</span>
          <div class="search-wrap">
            <input id="search-input" class="search-input" type="search" placeholder="Search prompts, host, client…" oninput="onSearchInput(this.value)">
          </div>
          <div class="ftabs">
            <button class="ftab active" onclick="setFilter('all',this)">All</button>
            <button class="ftab" onclick="setFilter('blocked',this)">Blocked</button>
            <button class="ftab" onclick="setFilter('redacted',this)">Redacted</button>
            <button class="ftab" onclick="setFilter('flagged',this)">Flagged</button>
            <button class="ftab" onclick="setFilter('telemetry',this)">Telemetry</button>
            <button class="ftab" onclick="setFilter('clean',this)">Clean</button>
          </div>
        </div>
        <div class="tbl-wrap">
          <table class="pg-tbl">
            <thead>
              <tr>
                <th>Time</th>
                <th>Status</th>
                <th>Host</th>
                <th>Path</th>
                <th>Rules Hit</th>
                <th>Latency</th>
                <th>Tokens (in/out)</th>
                <th style="text-align:center">CTX</th>
                <th>Session</th>
                <th>Client</th>
                <th>Model</th>
              </tr>
            </thead>
            <tbody id="prompts-body">
              <tr class="empty"><td colspan="11">No prompts intercepted yet</td></tr>
            </tbody>
          </table>
        </div>
        <div class="pagination">
          <span class="pg-info" id="pg-info"></span>
          <button class="pg-btn" id="pg-prev" onclick="goPage(currentPage-1)" disabled>&#8592; Prev</button>
          <button class="pg-btn" id="pg-next" onclick="goPage(currentPage+1)" disabled>Next &#8594;</button>
          <select class="pg-select" id="pg-size" onchange="setPageSize(+this.value)">
            <option value="25">25 / page</option>
            <option value="50">50 / page</option>
            <option value="100">100 / page</option>
          </select>
        </div>
      </div>
    </div>

    <!-- Rules panel -->
    <div class="rules-panel-wrap">
      <div class="rules-panel-inner">
        <div class="panel">
          <div class="panel-hd" style="display:flex;align-items:center">
            <span class="panel-title">Detection Rules</span>
            <span class="panel-count" id="rules-count">0</span>
            <button class="rules-toggle-btn" onclick="toggleRulesPanel()" title="Collapse rules panel">›</button>
          </div>
          <div class="rules-search-wrap">
            <input id="rules-search" class="rules-search-input" type="search" placeholder="Filter rules…" oninput="filterRules()">
          </div>
          <div id="rules-list" style="max-height:calc(100vh - 165px);overflow-y:auto"></div>
        </div>
      </div>
      <div class="rules-collapsed-strip" onclick="toggleRulesPanel()" title="Expand rules panel">
        <span class="rules-collapsed-arrow">‹</span>
        <span class="rules-collapsed-label">Detection Rules</span>
      </div>
    </div>
  </div>

</main>

<script>
var currentFilter = 'all';
var currentSearch = '';
var currentPage   = 1;
var pageSize      = 25;
var _searchTimer  = null;
var _ctxLimits    = { default: 200000 }; // populated from /api/context-limits

// Returns the context limit for a given client string by prefix-matching the
// configured keys. Falls back to "default".
function ctxLimitFor(client) {
  if (!client) return _ctxLimits.default || 200000;
  var keys = Object.keys(_ctxLimits).filter(function(k){ return k !== 'default'; });
  for (var i = 0; i < keys.length; i++) {
    if (client.toLowerCase().indexOf(keys[i].toLowerCase()) !== -1) {
      return _ctxLimits[keys[i]];
    }
  }
  return _ctxLimits.default || 200000;
}

function onSearchInput(val) {
  clearTimeout(_searchTimer);
  _searchTimer = setTimeout(function() {
    currentSearch = val.trim();
    currentPage   = 1;
    lastTopId     = null;
    refresh();
  }, 300);
}
var openRow       = null;

function toggleTheme() {
  var html = document.documentElement;
  var next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  localStorage.setItem('pg-theme', next);
  updateThemeIcon(next);
}
function updateThemeIcon(t) {
  var sun  = document.getElementById('theme-icon-sun');
  var moon = document.getElementById('theme-icon-moon');
  if (!sun || !moon) return;
  // In dark mode show sun (click → go light). In light mode show moon (click → go dark).
  sun.style.display  = t === 'dark'  ? '' : 'none';
  moon.style.display = t === 'light' ? '' : 'none';
}
(function(){ updateThemeIcon(document.documentElement.getAttribute('data-theme')); })();


function fmtTokens(n) {
  if (n >= 1000000) return (n/1000000).toFixed(1)+'M';
  if (n >= 1000)    return (n/1000).toFixed(1)+'K';
  return String(n);
}

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function statusTag(s) { return '<span class="tag tag-'+esc(s)+'">'+esc(s)+'</span>'; }
function sevTag(s)    { return s ? '<span class="tag tag-'+esc(s)+'">'+esc(s)+'</span>' : ''; }
function modeTag(m)   { return '<span class="mm mm-'+esc(m)+'">'+esc(m)+'</span>'; }

function setFilter(f, btn) {
  currentFilter = f;
  currentPage   = 1;
  lastTopId     = null;
  document.querySelectorAll('.ftab').forEach(function(b){ b.classList.remove('active'); });
  btn.classList.add('active');
  refresh();
}

function goPage(p) {
  currentPage = p;
  lastTopId   = null;
  refresh();
}

function setPageSize(n) {
  pageSize    = n;
  currentPage = 1;
  lastTopId   = null;
  refresh();
}

function toggleDetail(id) {
  var existing = document.getElementById('detail-'+id);
  if (existing) {
    existing.remove();
    openRow = null;
    return;
  }
  openRow = id;
  var anchor = document.getElementById('row-'+id);
  if (!anchor) return;

  var p = (window._promptData || {})[id] || {};
  var prompt         = p.prompt          || '';
  var redactedPrompt = p.redacted_prompt || '';
  var matches = p.matches || [];
  var status  = p.status  || '';

  var banner = '';
  if (status === 'blocked') {
    banner = '<div class="banner banner-blocked">⛔ Prompt was blocked — not forwarded to AI</div>';
  } else if (status === 'redacted') {
    banner = '<div class="banner banner-redacted">✂ Sensitive data was redacted before forwarding to AI</div>';
  }

  var promptSection;
  if (redactedPrompt && redactedPrompt !== prompt) {
    promptSection =
      '<div class="detail-section-lbl">Original prompt</div>' +
      '<div class="detail-pre">'+esc(prompt)+'</div>' +
      '<div class="detail-section-lbl lbl-purple" style="margin-top:4px">Sent to AI (after redaction)</div>' +
      '<div class="detail-pre" style="border-color:rgba(167,139,250,.3)">'+esc(redactedPrompt)+'</div>';
  } else {
    promptSection = '<div class="detail-pre">'+esc(prompt)+'</div>';
  }

  var matchHTML = matches.length === 0
    ? '<div style="color:var(--text-3);font-size:11.5px">No rules matched</div>'
    : matches.map(function(m) {
        return '<div class="match-item">' +
          '<div class="match-meta">'+sevTag(m.severity)+modeTag(m.mode)+'</div>' +
          '<div style="min-width:0">' +
            '<div style="font-weight:600;font-size:11.5px;margin-bottom:3px">'+esc(m.rule_name)+'</div>' +
            '<div class="match-snippet">'+esc(m.snippet)+'</div>' +
          '</div></div>';
      }).join('');

  var tokenInfo = '';
  if (p.input_tokens || p.output_tokens) {
    tokenInfo = '<div style="font-size:11px;color:var(--text-3);margin-top:8px">'+
      'Context sent: <span style="color:var(--text-2)">'+fmtTokens(p.input_tokens||0)+'</span> tokens &nbsp;·&nbsp; '+
      'Response: <span style="color:var(--text-2)">'+fmtTokens(p.output_tokens||0)+'</span> tokens'+
      '</div>';
  }

  var detail = document.createElement('tr');
  detail.id = 'detail-'+id;
  detail.className = 'detail-row';
  var td = document.createElement('td');
  td.colSpan = 11;
  td.innerHTML =
    '<div class="detail-wrap">' +
      banner + promptSection + tokenInfo +
      '<div class="detail-section-lbl" style="margin-top:14px;margin-bottom:6px">Matched Rules</div>' +
      '<div class="match-list">'+matchHTML+'</div>' +
    '</div>';
  detail.appendChild(td);
  anchor.after(detail);
}

var lastTopId = null;
var _refreshTick = 0;

async function refresh() {
  _refreshTick++;
  if (_refreshTick % 3 === 1) refreshModelStats(); // every ~9s, in sync with main timer
  try {
    var qs = '?page='+currentPage+'&per_page='+pageSize+(currentFilter !== 'all' ? '&status='+currentFilter : '')+(currentSearch ? '&search='+encodeURIComponent(currentSearch) : '');
    var [pr, sr] = await Promise.all([fetch('/api/prompts'+qs), fetch('/api/stats')]);
    var data  = await pr.json();
    var stats = await sr.json();

    var prompts  = data.items  || [];
    var total    = data.total  || 0;
    var totalPages = Math.max(1, Math.ceil(total / pageSize));
    if (currentPage > totalPages) { currentPage = totalPages; }

    document.getElementById('meta').textContent = new Date().toLocaleTimeString();
    document.getElementById('tile-total').textContent    = stats.total    || 0;
    document.getElementById('tile-clean').textContent    = stats.clean    || 0;
    document.getElementById('tile-flagged').textContent  = stats.flagged  || 0;
    document.getElementById('tile-redacted').textContent = stats.redacted || 0;
    document.getElementById('tile-blocked').textContent    = stats.blocked   || 0;
    document.getElementById('tile-telemetry').textContent = stats.telemetry || 0;
    document.getElementById('tile-host').textContent      = stats.most_flagged_host || '—';
    var inTok = stats.total_input_tokens||0;
    document.getElementById('tile-tokens').textContent = inTok > 0 ? fmtTokens(inTok) : '—';
    document.getElementById('prompt-count').textContent  = total;
    // Alert state: glow the blocked tile when there are active blocks; same for flagged
    var blockedTile = document.querySelector('.tile-blocked');
    var flaggedTile = document.querySelector('.tile-flagged');
    if (blockedTile) blockedTile.classList.toggle('tile--alert', (stats.blocked || 0) > 0);
    if (flaggedTile) flaggedTile.classList.toggle('tile--alert', (stats.flagged || 0) > 0);

    // Pagination controls
    var start = (currentPage-1)*pageSize+1;
    var end   = Math.min(currentPage*pageSize, total);
    document.getElementById('pg-info').textContent = total === 0 ? '' : start+'-'+end+' of '+total;
    document.getElementById('pg-prev').disabled = currentPage <= 1;
    document.getElementById('pg-next').disabled = currentPage >= totalPages;

    var newTopId = prompts.length > 0 ? prompts[0].id : null;
    if (newTopId === lastTopId && currentPage > 1 && !currentSearch) return; // stable inner page — skip re-render
    lastTopId = newTopId;

    window._promptData = {};
    prompts.forEach(function(p){ window._promptData[p.id] = p; });
    var wasOpen = openRow;

    document.getElementById('prompts-body').innerHTML = prompts.length === 0
      ? '<tr class="empty"><td colspan="11">' +
          (currentFilter !== 'all'
            ? 'No ' + esc(currentFilter) + ' prompts in this time window.'
            : 'No prompts intercepted yet.<br><span style="font-size:12px;font-weight:400">Route your AI traffic through the proxy to start seeing requests here.</span>'
          ) + '</td></tr>'
      : prompts.map(function(p) {
          var shortPath = p.path.replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, '/…');
          // Rules Hit: render each matched rule as a small chip instead of comma-joined string.
          // Max 3 chips shown; overflow shown as "+N more" to keep the column scannable.
          var rules = p.rules || [];
          var rulesHTML;
          if (rules.length === 0) {
            rulesHTML = '<span style="color:var(--text-3)">—</span>';
          } else {
            var chips = rules.slice(0, 3).map(function(r) {
              return '<span style="display:inline-flex;align-items:center;background:var(--bg-raised);' +
                     'border:1px solid var(--border);border-radius:4px;padding:1px 7px;font-size:11px;' +
                     'color:var(--text-2);white-space:nowrap;margin-right:3px">' + esc(r) + '</span>';
            });
            if (rules.length > 3) {
              chips.push('<span style="font-size:11px;color:var(--text-3)">+' + (rules.length - 3) + ' more</span>');
            }
            rulesHTML = '<div style="display:flex;flex-wrap:wrap;gap:2px;align-items:center">' + chips.join('') + '</div>';
          }
          var dur = p.duration_ms > 0
            ? (p.duration_ms >= 1000
                ? (p.duration_ms/1000).toFixed(1)+'s'
                : p.duration_ms+'ms')
            : '<span style="color:var(--text-3)">—</span>';
          var agentBadge = p.agent_mode ? '<span style="display:block;margin-top:3px;font-size:9px;font-weight:700;letter-spacing:.4px;text-transform:uppercase;color:#f59e0b;background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.3);border-radius:4px;padding:1px 5px;width:fit-content;">ag</span>' : '';
          var sid = p.session_id || '';
          var sessionCell = sid
            ? '<td class="mono muted td-r" title="'+esc(sid)+'">'+esc(sid.slice(0,8))+'</td>'
            : '<td class="mono muted td-r" style="color:var(--text-3)">—</td>';
          var clientVal = p.client || '';
          var clientCell = clientVal
            ? '<td class="mono muted" title="'+esc(clientVal)+'">'+esc(clientVal)+'</td>'
            : '<td class="mono muted" style="color:var(--text-3)">—</td>';
          var modelVal = p.model || '';
          var modelCell = modelVal
            ? '<td class="mono muted" title="'+esc(modelVal)+'">'+esc(modelVal)+'</td>'
            : '<td class="mono muted" style="color:var(--text-3)">—</td>';
          return '<tr id="row-'+p.id+'" class="row-'+p.status+'" onclick="toggleDetail('+p.id+')">' +
            '<td class="mono muted">'+esc(p.time)+'</td>' +
            '<td>'+statusTag(p.status)+agentBadge+'</td>' +
            '<td class="td-host" title="'+esc(p.host)+'">'+esc(p.host)+'</td>' +
            '<td class="mono muted td-path" title="'+esc(p.path)+'">'+esc(shortPath)+'</td>' +
            '<td>'+rulesHTML+'</td>' +
            '<td class="mono muted td-r">'+dur+'</td>' +
            '<td class="mono muted td-r">'+(p.input_tokens||p.output_tokens ? fmtTokens(p.input_tokens||0)+' / '+fmtTokens(p.output_tokens||0) : '—')+'</td>' +
            (function(){
              if (!p.input_tokens) return '<td style="text-align:center"><span style="color:var(--text-3);font-size:11px">—</span></td>';
              var lim = ctxLimitFor(p.client);
              var pct = Math.min(Math.round(p.input_tokens / lim * 100), 100);
              var col = pct >= 90 ? '#ef4444' : pct >= 75 ? '#f59e0b' : '#22c55e';
              var tip = pct+'% of '+fmtTokens(lim)+' ctx limit'+(pct>=90?' — start new session':pct>=75?' — approaching limit':'');
              return '<td style="text-align:center"><span title="'+tip+'" style="display:inline-block;width:10px;height:10px;border-radius:50%;background:'+col+'"></span></td>';
            })()+
            sessionCell +
            clientCell +
            modelCell +
            '</tr>';
        }).join('');

    if (wasOpen && document.getElementById('row-'+wasOpen)) {
      toggleDetail(wasOpen);
    }

  } catch(e) {
    document.getElementById('meta').textContent = 'error: '+e.message;
  }
}

var _allRules = [];

function ruleLabel(r) {
  // Use Name if it differs from ID (hand-rolled rules have proper names).
  // For gitleaks rules Name === ID, so convert kebab-case to Title Case.
  if (r.name && r.name !== r.id) return r.name;
  return r.id.replace(/-/g, ' ').replace(/\b\w/g, function(c){ return c.toUpperCase(); });
}

function renderRules(rules) {
  var groups = {'high': [], 'medium': [], 'low': []};
  rules.forEach(function(r){ (groups[r.severity] || groups['low']).push(r); });
  var html = '';
  [['high','High'], ['medium','Medium'], ['low','Low']].forEach(function(pair) {
    var sev = pair[0], label = pair[1];
    var list = groups[sev];
    if (!list.length) return;
    html += '<div class="rules-group-hd sev-hd-'+sev+'">'+label+' <span style="opacity:.5;font-weight:400">('+list.length+')</span></div>';
    html += list.map(function(r) {
      var isBlock = r.mode === 'block';
      var isTrack = r.mode === 'track';
      return '<div class="rule-card sev-'+sev+'">' +
        '<div class="rule-top">' +
          '<div class="rule-info">' +
            '<div class="rule-name" title="'+esc(r.id)+'">'+esc(ruleLabel(r))+'</div>' +
          '</div>' +
          '<div class="seg" id="seg-'+esc(r.id)+'">' +
            '<button class="seg-btn '+(isTrack?'seg-active-track':'')+'" onclick="setMode(\''+esc(r.id)+'\',\'track\',this)">Track</button>' +
            '<button class="seg-btn '+(isBlock?'seg-active-block':'')+'" onclick="setMode(\''+esc(r.id)+'\',\'block\',this)">Block</button>' +
          '</div>' +
        '</div>' +
        '<div class="rule-desc">'+esc(r.description)+'</div>' +
        '</div>';
    }).join('');
  });
  document.getElementById('rules-list').innerHTML = html;
}

function filterRules() {
  var q = (document.getElementById('rules-search').value || '').toLowerCase();
  if (!q) { renderRules(_allRules); return; }
  renderRules(_allRules.filter(function(r){
    return r.name.toLowerCase().includes(q) || r.id.toLowerCase().includes(q) || r.description.toLowerCase().includes(q);
  }));
}

async function loadRules() {
  try {
    _allRules = await fetch('/api/rules').then(function(r){ return r.json(); });
    document.getElementById('rules-count').textContent = _allRules.length;
    renderRules(_allRules);
  } catch(e) { /* ignore */ }
}

async function setMode(ruleID, mode, btn) {
  var seg = document.getElementById('seg-'+ruleID);
  if (seg) seg.querySelectorAll('.seg-btn').forEach(function(b){ b.disabled = true; });
  try {
    await fetch('/api/rules/'+ruleID+'/mode', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({mode: mode}),
    });
    lastTopId = null; // force prompt list re-render after rule change
    await Promise.all([refresh(), loadRules()]);
  } finally {
    if (seg) seg.querySelectorAll('.seg-btn').forEach(function(b){ b.disabled = false; });
  }
}

async function toggleAgentMode() {
  var res = await fetch('/api/agent-mode', { method: 'POST' });
  var data = await res.json();
  updateAgentModeUI(data.agent_mode);
}

function updateAgentModeUI(on) {
  var btn = document.getElementById('agent-btn');
  var state = document.getElementById('agent-btn-state');
  btn.classList.toggle('is-on', on);
  state.textContent = on ? 'ON' : 'OFF';
}

async function clearAllPrompts() {
  if (!confirm('Clear all intercepted prompts? This cannot be undone.')) return;
  await fetch('/api/prompts', { method: 'DELETE' });
  lastTopId = null;
  await refresh();
}

function toggleRulesPanel() {
  document.body.classList.toggle('rules-collapsed');
  try { localStorage.setItem('rules-collapsed', document.body.classList.contains('rules-collapsed')); } catch(e) {}
}
// Restore collapsed state across page reloads.
try { if (localStorage.getItem('rules-collapsed') === 'true') document.body.classList.add('rules-collapsed'); } catch(e) {}

refresh();
refreshModelStats().then(restoreLatencyPanel);
loadRules();
fetch('/api/agent-mode').then(function(r){ return r.json(); }).then(function(d){ updateAgentModeUI(d.agent_mode); });
fetch('/api/context-limits').then(function(r){ return r.json(); }).then(function(d){ _ctxLimits = d; });

async function refreshModelStats() {
  try {
    var stats = await fetch('/api/model-stats').then(function(r){ return r.json(); });
    var row     = document.getElementById('model-latency-row');
    var body    = document.getElementById('model-latency-body');
    var summary = document.getElementById('latency-summary');
    if (!stats || stats.length === 0) { row.style.display = 'none'; return; }
    row.style.display = 'block';

    var fmt  = function(ms) { return ms >= 1000 ? (ms/1000).toFixed(1)+'s' : ms+'ms'; };
    var colr = function(ms) { return ms > 10000 ? 'var(--danger)' : ms > 5000 ? 'var(--warning)' : '#4caf82'; };
    var trunc = function(s, n) { return s.length > n ? s.slice(0, n-1) + '\u2026' : s; };

    // Group by model; collect unique clients.
    var byModel = {}, modelOrder = [], clients = [];
    stats.forEach(function(s) {
      var m = s.model||'', c = s.client||'';
      if (!byModel[m]) { byModel[m] = {}; modelOrder.push(m); }
      byModel[m][c] = s;
      if (clients.indexOf(c) < 0) clients.push(c);
    });
    modelOrder.sort(); clients.sort();
    if (summary) summary.textContent = modelOrder.length + ' model' + (modelOrder.length === 1 ? '' : 's')
      + ' \u00b7 ' + clients.length + ' client' + (clients.length === 1 ? '' : 's');

    // Style fragments
    var thModel = 'padding:3px 10px 5px;font-size:10px;font-weight:600;letter-spacing:0.04em;text-transform:uppercase;color:var(--text-3);border-top:1px solid var(--border);border-bottom:1px solid var(--border);text-align:left;vertical-align:bottom;white-space:nowrap;border-left:1px solid var(--border)';
    var thClient = 'padding:4px 10px 2px;font-size:10px;font-weight:600;letter-spacing:0.03em;text-transform:uppercase;color:var(--text-2);text-align:center;white-space:nowrap;border-top:1px solid var(--border);border-bottom:1px solid var(--border);border-left:1px solid var(--border)';
    var thSub = function(first) {
      return 'padding:2px 8px 4px;font-size:10px;font-weight:500;color:var(--text-3);text-align:right;border-bottom:1px solid var(--border);white-space:nowrap' + (first ? ';border-left:1px solid var(--border)' : '');
    };
    var tdModel = 'padding:4px 10px;font-size:11px;text-align:left;color:var(--text-2);border-left:1px solid var(--border)';
    var tdNum = function(first) {
      return 'padding:4px 8px;font-size:11px;font-variant-numeric:tabular-nums;text-align:right;white-space:nowrap' + (first ? ';border-left:1px solid var(--border)' : '');
    };
    // Corner cell: CLIENT (same size as Model) at top, Model at bottom.
    var cornerCell = '<th rowspan="2" style="'+thModel+';padding:0;width:140px">' +
      '<div style="display:flex;flex-direction:column;justify-content:space-between;height:100%;min-height:44px;padding:4px 10px 5px">' +
        '<span style="font-size:10px;font-weight:600;letter-spacing:0.04em;text-transform:uppercase;color:var(--text-3)">CLIENT</span>' +
        '<span>Model</span>' +
      '</div></th>';

    // 2-row pivot header: corner | client group names | then p50/p95/n row
    var html = '<table style="table-layout:auto;width:100%;border-collapse:collapse"><thead>';
    html += '<tr>' + cornerCell;
    clients.forEach(function(c) {
      html += '<th colspan="3" style="'+thClient+'" title="'+esc(c||'unknown')+'">'+esc(trunc(c||'unknown', 20))+'</th>';
    });
    html += '</tr><tr>';
    clients.forEach(function() {
      html += '<th style="'+thSub(true)+'">p50</th><th style="'+thSub(false)+'">p95</th><th style="'+thSub(false)+'">n</th>';
    });
    html += '</tr></thead><tbody>';

    // One row per model.
    modelOrder.forEach(function(m, i) {
      var bg = i % 2 === 1 ? 'background:rgba(0,0,0,0.035)' : '';
      html += '<tr style="'+bg+'"><td style="'+tdModel+'"><div style="width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(m)+'">'+esc(m)+'</div></td>';
      clients.forEach(function(c) {
        var s = byModel[m] && byModel[m][c];
        if (s) {
          html += '<td style="'+tdNum(true)+';color:var(--text-1);font-weight:600">'+fmt(s.p50_ms)+'</td>';
          html += '<td style="'+tdNum(false)+';color:'+colr(s.p95_ms)+';font-weight:600">'+fmt(s.p95_ms)+'</td>';
          html += '<td style="'+tdNum(false)+';color:var(--text-3);font-size:10px">'+s.sample+'</td>';
        } else {
          html += '<td style="'+tdNum(true)+';color:var(--text-3)">\u2014</td>';
          html += '<td style="'+tdNum(false)+';color:var(--text-3)">\u2014</td>';
          html += '<td style="'+tdNum(false)+';color:var(--text-3);font-size:10px">\u2014</td>';
        }
      });
      html += '</tr>';
    });
    html += '</tbody></table>';
    body.innerHTML = html;

    // Re-fit height if panel open.
    var wrap = document.getElementById('latency-table-wrap');
    var btn  = document.getElementById('latency-toggle');
    if (wrap && btn && btn.getAttribute('aria-expanded') === 'true') wrap.style.height = 'auto';
  } catch(e) {}
}

function toggleLatencyPanel() {
  var wrap = document.getElementById('latency-table-wrap');
  var chevron = document.getElementById('latency-chevron');
  var btn = document.getElementById('latency-toggle');
  var isOpen = btn.getAttribute('aria-expanded') === 'true';
  if (isOpen) {
    _animateHeight(wrap, wrap.offsetHeight, 0, 160, function() { wrap.style.overflow = 'hidden'; });
    chevron.style.transform = 'rotate(0deg)';
    btn.setAttribute('aria-expanded', 'false');
    try { localStorage.setItem('latencyPanelOpen', '0'); } catch(e) {}
  } else {
    wrap.style.overflow = 'hidden';
    _animateHeight(wrap, 0, wrap.scrollHeight, 160, function() { wrap.style.height = 'auto'; });
    chevron.style.transform = 'rotate(90deg)';
    btn.setAttribute('aria-expanded', 'true');
    try { localStorage.setItem('latencyPanelOpen', '1'); } catch(e) {}
  }
}

// Smooth height animation using requestAnimationFrame (ease-out cubic).
// Avoids max-height layout jank and subpixel border clipping from overflow:hidden on parent.
function _animateHeight(el, from, to, durationMs, onDone) {
  var start = null;
  el.style.height = from + 'px';
  function step(ts) {
    if (!start) start = ts;
    var t = Math.min((ts - start) / durationMs, 1);
    var ease = 1 - Math.pow(1 - t, 3); // ease-out cubic
    el.style.height = (from + (to - from) * ease) + 'px';
    if (t < 1) { requestAnimationFrame(step); } else { if (onDone) onDone(); }
  }
  requestAnimationFrame(step);
}

function restoreLatencyPanel() {
  try {
    if (localStorage.getItem('latencyPanelOpen') === '1') {
      var wrap = document.getElementById('latency-table-wrap');
      var chevron = document.getElementById('latency-chevron');
      var btn = document.getElementById('latency-toggle');
      if (wrap) {
        wrap.style.height = 'auto';
        wrap.style.overflow = '';
        chevron.style.transform = 'rotate(90deg)';
        btn.setAttribute('aria-expanded', 'true');
      }
    }
  } catch(e) {}
}

// ── Refresh interval control ──────────────────────────────────────────────────
var _refreshTimer = null;

var _refreshIntervals = [
  { label: '5s',  ms: 5000  },
  { label: '15s', ms: 15000 },
  { label: '30s', ms: 30000 },
  { label: '1m',  ms: 60000 },
  { label: 'Off', ms: 0     },
];
var _refreshMs = 15000; // default

function _startRefreshTimer() {
  if (_refreshTimer) clearInterval(_refreshTimer);
  if (_refreshMs > 0) {
    _refreshTimer = setInterval(function() {
      if (document.visibilityState !== 'hidden') refresh();
    }, _refreshMs);
  }
}

function setRefreshInterval(ms) {
  _refreshMs = ms;
  try { localStorage.setItem('pg-refresh-ms', ms); } catch(e) {}
  _startRefreshTimer();
  // Update selector UI
  document.querySelectorAll('.ri-opt').forEach(function(el) {
    el.classList.toggle('ri-opt-active', parseInt(el.dataset.ms) === ms);
  });
}

function manualRefresh() {
  refresh();
  refreshModelStats();
}

// Restore saved preference
try {
  var saved = parseInt(localStorage.getItem('pg-refresh-ms'));
  if (!isNaN(saved) && _refreshIntervals.some(function(r){ return r.ms === saved; })) _refreshMs = saved;
} catch(e) {}

// Build interval buttons into the header widget
(function() {
  var wrap = document.getElementById('ri-wrap');
  _refreshIntervals.forEach(function(r) {
    var btn = document.createElement('button');
    btn.className = 'ri-opt' + (r.ms === _refreshMs ? ' ri-opt-active' : '');
    btn.dataset.ms = r.ms;
    btn.textContent = r.label;
    btn.title = r.ms > 0 ? 'Auto-refresh every ' + r.label : 'Disable auto-refresh';
    btn.onclick = function() { setRefreshInterval(r.ms); };
    wrap.appendChild(btn);
  });
})();

_startRefreshTimer();
document.addEventListener('visibilitychange', function() {
  if (document.visibilityState === 'visible') { refresh(); _startRefreshTimer(); }
  else { if (_refreshTimer) clearInterval(_refreshTimer); _refreshTimer = null; }
});

function toggleExport() {
  var p = document.getElementById('export-panel');
  p.style.display = p.style.display === 'none' ? 'block' : 'none';
  if (p.style.display === 'block') document.getElementById('tester-panel').style.display = 'none';
}

function toggleTester() {
  var p = document.getElementById('tester-panel');
  var b = document.getElementById('tester-backdrop');
  var open = p.style.display !== 'block';
  p.style.display = open ? 'block' : 'none';
  b.style.display = open ? 'block' : 'none';
  if (open) {
    document.getElementById('export-panel').style.display = 'none';
    document.getElementById('tester-input').focus();
  }
}

function clearTester() {
  document.getElementById('tester-input').value = '';
  document.getElementById('tester-results').style.display = 'none';
  document.getElementById('tester-input').focus();
}

async function runScan() {
  var text = document.getElementById('tester-input').value.trim();
  if (!text) return;
  var btn = document.getElementById('scan-btn');
  btn.textContent = 'Scanning…'; btn.disabled = true;
  try {
    var res = await fetch('/api/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({text: text})});
    var data = await res.json();
    renderScanResult(data);
  } catch(e) {
    alert('Scan failed: ' + e);
  } finally {
    btn.textContent = 'Scan'; btn.disabled = false;
  }
}

function renderScanResult(data) {
  var results = document.getElementById('tester-results');
  results.style.display = 'block';
  var badge = document.getElementById('tester-status-badge');
  var colors = {blocked:'#e05252', redacted:'#c49a2a', clean:'#3fa66e'};
  badge.textContent = data.status.toUpperCase();
  badge.style.background = colors[data.status] || '#888';
  badge.style.color = '#fff';

  var matchesEl = document.getElementById('tester-matches');
  if (data.matches && data.matches.length > 0) {
    matchesEl.style.display = 'block';
    matchesEl.innerHTML = data.matches.map(function(m) {
      var sevColor = m.severity === 'high' ? '#e05252' : m.severity === 'medium' ? '#c49a2a' : '#3fa66e';
      var modeColor = m.mode === 'block' ? '#e05252' : '#3fa66e';
      return '<div style="background:var(--bg-raised);border:1px solid var(--border);border-radius:6px;padding:7px 10px;margin-bottom:5px;font-size:11px">' +
        '<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">' +
        '<span style="font-weight:600;color:var(--text-1)">' + escHtml(m.rule_name) + '</span>' +
        '<span style="background:' + sevColor + ';color:#fff;border-radius:3px;padding:1px 6px;font-size:10px">' + m.severity + '</span>' +
        '<span style="background:' + modeColor + ';color:#fff;border-radius:3px;padding:1px 6px;font-size:10px">' + m.mode + '</span>' +
        '</div>' +
        '<div style="color:var(--text-3);font-family:monospace;font-size:10.5px;word-break:break-all">' + escHtml(m.snippet) + '</div>' +
        '</div>';
    }).join('');
  } else {
    matchesEl.style.display = 'none';
  }

  var redactWrap = document.getElementById('tester-redacted-wrap');
  if (data.status === 'redacted' && data.redacted !== data.original) {
    redactWrap.style.display = 'block';
    document.getElementById('tester-redacted-text').textContent = data.redacted;
  } else {
    redactWrap.style.display = 'none';
  }
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function doExport(preset) {
  var from = '', to = '';
  var now = new Date();
  var pad = function(n){ return String(n).padStart(2,'0'); };
  var fmt = function(d){ return d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate()); };

  if (preset === 'today') {
    from = fmt(now); to = fmt(now);
  } else if (preset === '7d') {
    var d = new Date(now); d.setDate(d.getDate()-6);
    from = fmt(d); to = fmt(now);
  } else if (preset === '30d') {
    var d = new Date(now); d.setDate(d.getDate()-29);
    from = fmt(d); to = fmt(now);
  } else if (preset === 'custom') {
    from = document.getElementById('exp-from').value;
    to   = document.getElementById('exp-to').value;
  }

  var url = '/api/export';
  var params = [];
  if (from) params.push('from='+from);
  if (to)   params.push('to='+to);
  if (params.length) url += '?' + params.join('&');

  window.location.href = url;
  document.getElementById('export-panel').style.display = 'none';
}

// Close export panel when clicking outside
document.addEventListener('click', function(e) {
  var panel = document.getElementById('export-panel');
  var btn   = document.getElementById('export-btn');
  if (panel.style.display !== 'none' && !panel.contains(e.target) && e.target !== btn) {
    panel.style.display = 'none';
  }
});
</script>
</body>
</html>
`

var _ = time.Now

var logoSVG = `<svg width="680" height="680" viewBox="0 0 680 680" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#1e2a5e"/>
      <stop offset="100%" stop-color="#2a1050"/>
    </linearGradient>
    <clipPath id="shieldClip">
      <path d="M340 160 L500 210 L500 360 Q500 460 340 530 Q180 460 180 360 L180 210 Z"/>
    </clipPath>
    <mask id="outsideShieldMask">
      <circle cx="340" cy="340" r="300" fill="white"/>
      <path d="M340 160 L500 210 L500 360 Q500 460 340 530 Q180 460 180 360 L180 210 Z" fill="black"/>
    </mask>
  </defs>
  <circle cx="340" cy="340" r="300" fill="#0d0f1a"/>
  <circle cx="340" cy="340" r="300" fill="#f97316" mask="url(#outsideShieldMask)"/>
  <circle cx="340" cy="340" r="295" fill="none" stroke="#4a7fff" stroke-width="0.5" opacity="0.18"/>
  <circle cx="340" cy="340" r="285" fill="none" stroke="#a855f7" stroke-width="0.5" opacity="0.1"/>
  <path d="M340 160 L500 210 L500 360 Q500 460 340 530 Q180 460 180 360 L180 210 Z" fill="url(#shieldGrad)"/>
  <path d="M340 160 L500 210 L500 360 Q500 460 340 530 Q180 460 180 360 L180 210 Z" fill="none" stroke="#4a7fff" stroke-width="1.5" opacity="0.7"/>
  <path d="M340 160 L500 210 L500 360 Q500 460 340 530 Q180 460 180 360 L180 210 Z" fill="none" stroke="#a855f7" stroke-width="0.5" opacity="0.5"/>
  <g clip-path="url(#shieldClip)">
    <line x1="267" y1="250" x2="313" y2="300" stroke="#4a7fff" stroke-width="1.6" opacity="0.7"/>
    <line x1="267" y1="250" x2="340" y2="285" stroke="#6a5fff" stroke-width="1.6" opacity="0.7"/>
    <line x1="267" y1="250" x2="367" y2="300" stroke="#8b5cf6" stroke-width="1.4" opacity="0.6"/>
    <line x1="340" y1="230" x2="313" y2="300" stroke="#4a7fff" stroke-width="1.6" opacity="0.75"/>
    <line x1="340" y1="230" x2="340" y2="285" stroke="#6a5fff" stroke-width="2" opacity="0.85"/>
    <line x1="340" y1="230" x2="367" y2="300" stroke="#8b5cf6" stroke-width="1.6" opacity="0.75"/>
    <line x1="413" y1="250" x2="313" y2="300" stroke="#8b5cf6" stroke-width="1.4" opacity="0.6"/>
    <line x1="413" y1="250" x2="340" y2="285" stroke="#6a5fff" stroke-width="1.6" opacity="0.7"/>
    <line x1="413" y1="250" x2="367" y2="300" stroke="#a855f7" stroke-width="1.6" opacity="0.7"/>
    <line x1="313" y1="300" x2="295" y2="370" stroke="#4a7fff" stroke-width="1.6" opacity="0.7"/>
    <line x1="313" y1="300" x2="340" y2="355" stroke="#6a5fff" stroke-width="1.6" opacity="0.75"/>
    <line x1="313" y1="300" x2="385" y2="370" stroke="#8b5cf6" stroke-width="1.4" opacity="0.6"/>
    <line x1="340" y1="285" x2="295" y2="370" stroke="#4a7fff" stroke-width="1.6" opacity="0.7"/>
    <line x1="340" y1="285" x2="340" y2="355" stroke="#6a5fff" stroke-width="2" opacity="0.9"/>
    <line x1="340" y1="285" x2="385" y2="370" stroke="#a855f7" stroke-width="1.6" opacity="0.7"/>
    <line x1="367" y1="300" x2="295" y2="370" stroke="#8b5cf6" stroke-width="1.4" opacity="0.6"/>
    <line x1="367" y1="300" x2="340" y2="355" stroke="#6a5fff" stroke-width="1.6" opacity="0.75"/>
    <line x1="367" y1="300" x2="385" y2="370" stroke="#a855f7" stroke-width="1.6" opacity="0.7"/>
    <line x1="295" y1="370" x2="310" y2="435" stroke="#4a7fff" stroke-width="1.5" opacity="0.65"/>
    <line x1="295" y1="370" x2="340" y2="445" stroke="#6a5fff" stroke-width="1.5" opacity="0.65"/>
    <line x1="340" y1="355" x2="310" y2="435" stroke="#4a7fff" stroke-width="1.6" opacity="0.7"/>
    <line x1="340" y1="355" x2="340" y2="445" stroke="#6a5fff" stroke-width="2" opacity="0.85"/>
    <line x1="340" y1="355" x2="370" y2="435" stroke="#a855f7" stroke-width="1.6" opacity="0.7"/>
    <line x1="385" y1="370" x2="340" y2="445" stroke="#8b5cf6" stroke-width="1.5" opacity="0.65"/>
    <line x1="385" y1="370" x2="370" y2="435" stroke="#a855f7" stroke-width="1.5" opacity="0.65"/>
    <circle cx="267" cy="250" r="7" fill="#60a5fa"/>
    <circle cx="340" cy="230" r="8.5" fill="#818cf8"/>
    <circle cx="413" cy="250" r="7" fill="#c084fc"/>
    <circle cx="313" cy="300" r="6.5" fill="#60a5fa"/>
    <circle cx="340" cy="285" r="8" fill="#818cf8"/>
    <circle cx="367" cy="300" r="6.5" fill="#c084fc"/>
    <circle cx="295" cy="370" r="6.5" fill="#60a5fa"/>
    <circle cx="340" cy="355" r="8" fill="#818cf8"/>
    <circle cx="385" cy="370" r="6.5" fill="#c084fc"/>
    <circle cx="310" cy="435" r="6" fill="#60a5fa"/>
    <circle cx="340" cy="445" r="8" fill="#818cf8"/>
    <circle cx="370" cy="435" r="6" fill="#c084fc"/>
    <circle cx="340" cy="340" r="55" fill="none" stroke="#6a5fff" stroke-width="0.8" opacity="0.25"/>
    <circle cx="340" cy="340" r="80" fill="none" stroke="#6a5fff" stroke-width="0.6" opacity="0.15"/>
  </g>
  <path d="M340 168 L492 215 L492 360 Q492 453 340 521" fill="none" stroke="#ffffff" stroke-width="0.8" opacity="0.1"/>
</svg>`
