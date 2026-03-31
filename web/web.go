package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chaudharydeepak/prompt-guard/inspector"
	"github.com/chaudharydeepak/prompt-guard/store"
)

// Start runs the web dashboard on the given port. Non-blocking.
func Start(port int, db *store.Store, eng *inspector.Engine, configPath string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/prompts", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("/api/export", func(w http.ResponseWriter, r *http.Request) {
		apiExport(w, r, db)
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

	srv := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: mux}
	log.Printf("dashboard: http://localhost:%d", port)
	go func() { log.Fatal(srv.ListenAndServe()) }()
}

// ── API handlers ─────────────────────────────────────────────────────────────

func apiPrompts(w http.ResponseWriter, r *http.Request, db *store.Store) {
	statusFilter := r.URL.Query().Get("status")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 200 {
		perPage = 25
	}
	offset := (page - 1) * perPage

	total, err := db.CountPrompts(statusFilter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	prompts, err := db.ListPrompts(statusFilter, perPage, offset)
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
		text := p.Prompt
		if p.RedactedPrompt != "" {
			text = p.RedactedPrompt
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
  body { font-family: 'Inter', system-ui, sans-serif; background: var(--bg-base); color: var(--text-1); font-size: 13px; min-height: 100vh; }

  /* ── Header ────────────────────────────────────── */
  .hd { display: flex; align-items: center; gap: 12px; padding: 0 20px; height: 50px;
        background: var(--bg-surface); border-bottom: 1px solid var(--border);
        position: sticky; top: 0; z-index: 100; }
  .hd-logo { display: flex; align-items: center; gap: 8px; }
  .hd-shield { width: 28px; height: 28px; flex-shrink: 0; }
  .hd-name { font-weight: 700; font-size: 14px; letter-spacing: -.3px; }
  .hd-name em { color: var(--accent); font-style: normal; }
  .hd-sep { width: 1px; height: 18px; background: var(--border); }
  .hd-badge { background: var(--accent-dim); color: var(--accent); border: 1px solid rgba(59,130,246,.2);
              border-radius: 4px; padding: 1px 7px; font-size: 10.5px; font-weight: 600; letter-spacing: .2px; }
  .hd-meta { color: var(--text-3); font-size: 11px; }
  .hd-live { display: flex; align-items: center; gap: 5px; color: var(--success); font-size: 11px; font-weight: 600; }
  .hd-live::before { content:''; width:6px; height:6px; border-radius:50%; background:var(--success);
                     box-shadow:0 0 0 0 var(--success); animation:pulse 2s infinite; }
  @keyframes pulse { 0%{box-shadow:0 0 0 0 rgba(16,185,129,.5)} 70%{box-shadow:0 0 0 6px rgba(16,185,129,0)} 100%{box-shadow:0 0 0 0 rgba(16,185,129,0)} }
  .hd-spacer { flex: 1; }
  .icon-btn { border: 1px solid var(--border); background: var(--bg-raised); color: var(--text-2);
              border-radius: 6px; padding: 5px 9px; font-size: 13px; cursor: pointer; font-family: inherit;
              line-height: 1; display: flex; align-items: center; }
  .icon-btn:hover { background: var(--border); color: var(--text-1); }

  /* ── Layout ────────────────────────────────────── */
  .pg-main { padding: 18px 20px; max-width: 1280px; margin: 0 auto; }
  .pg-cols { display: grid; grid-template-columns: 1fr 290px; gap: 14px; align-items: start; }
  @media(max-width:880px) { .pg-cols { grid-template-columns: 1fr; } }

  /* ── Metric tiles ──────────────────────────────── */
  .tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px,1fr)); gap: 10px; margin-bottom: 16px; }
  .tile { background: var(--bg-surface); border: 1px solid var(--border); border-radius: 10px; padding: 13px 15px;
          position: relative; overflow: hidden; }
  .tile::before { content:''; position:absolute; top:0;left:0;right:0; height:2px; }
  .tile-total::before  { background: linear-gradient(90deg,var(--accent),transparent); }
  .tile-clean::before  { background: linear-gradient(90deg,var(--success),transparent); }
  .tile-flagged::before{ background: linear-gradient(90deg,var(--warning),transparent); }
  .tile-redacted::before{background: linear-gradient(90deg,var(--purple),transparent); }
  .tile-blocked::before{ background: linear-gradient(90deg,var(--danger),transparent); }
  .tile-host::before   { background: linear-gradient(90deg,var(--text-3),transparent); }
  .tile-lbl { font-size: 10.5px; font-weight: 600; text-transform: uppercase; letter-spacing: .5px; color: var(--text-3); margin-bottom: 7px; }
  .tile-val { font-size: 27px; font-weight: 700; line-height: 1; color: var(--text-1); }
  .tile-val.c-total   { color: var(--text-1); }
  .tile-val.c-clean   { color: var(--success); }
  .tile-val.c-flagged { color: var(--warning); }
  .tile-val.c-redacted{ color: var(--purple); }
  .tile-val.c-blocked { color: var(--danger); }
  .tile-sub { font-size: 11px; color: var(--text-3); margin-top: 4px; }
  .tile-host-val { font-size: 12px; font-weight: 600; padding-top: 5px; word-break: break-all; }

  /* ── Panel ─────────────────────────────────────── */
  .panel { background: var(--bg-surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; margin-bottom: 14px; }
  .panel-hd { display: flex; align-items: center; gap: 8px; padding: 11px 14px; border-bottom: 1px solid var(--border); flex-wrap: wrap; }
  .panel-title { font-weight: 600; font-size: 12.5px; }
  .panel-count { background: var(--bg-raised); border: 1px solid var(--border); border-radius: 20px;
                 padding: 1px 8px; font-size: 11px; color: var(--text-2); font-weight: 600; }

  /* ── Filter tabs ───────────────────────────────── */
  .ftabs { display: flex; gap: 3px; margin-left: auto; background: var(--bg-raised); border: 1px solid var(--border);
           border-radius: 6px; padding: 2px; }
  .ftab { border: none; background: transparent; color: var(--text-3); border-radius: 4px; padding: 3px 10px;
          font-size: 11px; font-weight: 600; cursor: pointer; font-family: inherit; letter-spacing: .1px; }
  .ftab:hover { color: var(--text-1); }
  .ftab.active { background: var(--bg-surface); color: var(--text-1);
                 box-shadow: 0 1px 3px rgba(0,0,0,.15); }

  /* ── Table ─────────────────────────────────────── */
  .tbl-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
  .pg-tbl { width: 100%; border-collapse: collapse; }
  .pg-tbl th { font-size: 10.5px; font-weight: 600; text-transform: uppercase; letter-spacing: .4px;
               color: var(--text-3); padding: 7px 14px; border-bottom: 1px solid var(--border);
               background: var(--bg-raised); white-space: nowrap; text-align: left; }
  .pg-tbl td { padding: 9px 14px; border-bottom: 1px solid var(--border-sub); color: var(--text-1);
               vertical-align: middle; white-space: nowrap; }
  .pg-tbl tr:last-child td { border-bottom: none; }
  .pg-tbl tbody tr { cursor: pointer; transition: background .1s; }
  .pg-tbl tbody tr:hover td { background: var(--bg-raised); }
  .pg-tbl .muted { color: var(--text-3); }
  .pg-tbl .mono  { font-family: 'SF Mono','Fira Code',Menlo,monospace; font-size: 11px; }
  .pg-tbl .empty td { color: var(--text-3); text-align: center; padding: 36px; cursor: default; }
  .pagination { display:flex; align-items:center; gap:6px; padding:10px 16px;
                border-top:1px solid var(--border); font-size:12px; color:var(--text-2); }
  .pagination .pg-info { flex:1; }
  .pg-btn { background:var(--bg-raised); border:1px solid var(--border); color:var(--text-1);
            padding:3px 10px; border-radius:5px; cursor:pointer; font-size:12px; }
  .pg-btn:disabled { opacity:.35; cursor:default; }
  .pg-btn:not(:disabled):hover { border-color:var(--accent); }
  .pg-select { background:var(--bg-raised); border:1px solid var(--border); color:var(--text-1);
               padding:3px 6px; border-radius:5px; font-size:12px; cursor:pointer; }
  .pg-tbl tr.row-blocked  td { background: var(--blocked-bg); }
  .pg-tbl tr.row-flagged  td { background: var(--flagged-bg); }
  .pg-tbl tr.row-redacted td { background: var(--redacted-bg); }

  /* ── Detail row ────────────────────────────────── */
  .detail-row td { background: var(--bg-input) !important; padding: 0 !important;
                   white-space: normal !important; cursor: default !important; }
  .detail-inner { padding: 14px 16px; }
  .detail-section-lbl { font-size: 10.5px; font-weight: 600; text-transform: uppercase; letter-spacing: .5px;
                        color: var(--text-3); margin-bottom: 5px; }
  .detail-section-lbl.lbl-purple { color: var(--purple); }
  .detail-pre { font-family: 'SF Mono','Fira Code',Menlo,monospace; font-size: 11px; color: var(--text-2);
                background: var(--bg-base); border: 1px solid var(--border); border-radius: 6px;
                padding: 10px 12px; margin-bottom: 10px; white-space: pre-wrap; word-break: break-word;
                max-height: 200px; overflow-y: auto; line-height: 1.6; }
  .banner { border-radius: 6px; padding: 8px 12px; margin-bottom: 12px; font-size: 12px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
  .banner-blocked  { background: var(--danger-dim);  border: 1px solid rgba(239,68,68,.25);  color: var(--danger);  }
  .banner-redacted { background: var(--purple-dim);  border: 1px solid rgba(167,139,250,.25); color: var(--purple); }
  .match-list { display: flex; flex-direction: column; gap: 5px; }
  .match-item { display: flex; align-items: flex-start; gap: 10px; background: var(--bg-surface);
                border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px; }
  .match-meta { display: flex; flex-direction: column; gap: 4px; min-width: 70px; }
  .match-snippet { font-family: 'SF Mono','Fira Code',Menlo,monospace; font-size: 10.5px; color: var(--text-2);
                   flex: 1; word-break: break-all; line-height: 1.5; }

  /* ── Tags ──────────────────────────────────────── */
  .tag { display: inline-flex; align-items: center; border-radius: 4px; padding: 2px 6px; font-size: 10px;
         font-weight: 700; letter-spacing: .3px; text-transform: uppercase; }
  .tag-high    { background: var(--danger-dim);  color: var(--danger);  border: 1px solid rgba(239,68,68,.25); }
  .tag-medium  { background: var(--warning-dim); color: var(--warning); border: 1px solid rgba(245,158,11,.25); }
  .tag-low     { background: var(--accent-dim);  color: var(--accent);  border: 1px solid rgba(59,130,246,.2); }
  .tag-blocked  { background: var(--danger-dim);  color: var(--danger);  border: 1px solid rgba(239,68,68,.3); }
  .tag-flagged  { background: var(--warning-dim); color: var(--warning); border: 1px solid rgba(245,158,11,.3); }
  .tag-redacted { background: var(--purple-dim);  color: var(--purple);  border: 1px solid rgba(167,139,250,.3); }
  .tag-clean    { background: var(--success-dim); color: var(--success); border: 1px solid rgba(16,185,129,.25); }
  .mm { font-size: 9.5px; font-weight: 700; text-transform: uppercase; padding: 1px 5px; border-radius: 3px; }
  .mm-block { background: var(--danger-dim);  color: var(--danger); }
  .mm-track { background: var(--accent-dim);  color: var(--accent); }

  /* ── Rule cards ────────────────────────────────── */
  .rule-card { padding: 10px 12px 10px 14px; border-bottom: 1px solid var(--border-sub);
               display: flex; flex-direction: column; gap: 7px;
               border-left: 3px solid transparent; transition: background .1s; }
  .rule-card:last-child { border-bottom: none; }
  .rule-card.sev-high   { border-left-color: var(--danger); }
  .rule-card.sev-medium { border-left-color: var(--warning); }
  .rule-card.sev-low    { border-left-color: var(--accent); }
  .rule-card:hover { background: var(--bg-raised); }
  .rule-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; }
  .rule-info { min-width: 0; }
  .rule-name { font-weight: 600; font-size: 12px; line-height: 1.3; }
  .rule-desc { color: var(--text-3); font-size: 10.5px; line-height: 1.4; margin-top: 2px; }
  .rule-foot { display: flex; align-items: center; justify-content: space-between; }

  /* Segmented control */
  .seg { display: flex; border: 1px solid var(--border); border-radius: 5px; overflow: hidden; flex-shrink: 0; }
  .seg-btn { border: none; background: transparent; color: var(--text-3); padding: 4px 11px;
             font-size: 10.5px; font-weight: 600; cursor: pointer; font-family: inherit;
             letter-spacing: .2px; transition: all .15s; }
  .seg-btn + .seg-btn { border-left: 1px solid var(--border); }
  .seg-btn:hover:not(.seg-active-track):not(.seg-active-block) { color: var(--text-1); background: var(--bg-raised); }
  .seg-btn.seg-active-track { background: var(--accent-dim);  color: var(--accent);  font-weight: 700; }
  .seg-btn.seg-active-block { background: var(--danger-dim);  color: var(--danger);  font-weight: 700; }
  .seg-btn:disabled { opacity: .5; cursor: wait; }
</style>
</head>
<body>

<header class="hd">
  <div class="hd-logo">
    <img src="/favicon.svg" class="hd-shield" alt="Prompt Guard">
    <div class="hd-name">Prompt<em>Guard</em></div>
  </div>
  <div class="hd-sep"></div>
  <div class="hd-badge">PROXY</div>
  <div class="hd-sep"></div>
  <div class="hd-live">Live</div>
  <div class="hd-sep"></div>
  <div class="hd-meta" id="meta">connecting…</div>
  <div class="hd-spacer"></div>
  <button class="icon-btn" onclick="toggleExport()" title="Export prompts" id="export-btn">⬇</button>
  <button class="icon-btn" onclick="toggleTheme()" title="Toggle theme" id="theme-btn">☀</button>
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
    <div class="tile tile-host">
      <div class="tile-lbl">Top Host</div>
      <div class="tile-host-val" id="tile-host">—</div>
      <div class="tile-sub">most hits</div>
    </div>
  </div>

  <div class="pg-cols">
    <!-- Prompts table -->
    <div>
      <div class="panel">
        <div class="panel-hd">
          <span class="panel-title">Prompts</span>
          <span class="panel-count" id="prompt-count">0</span>
          <div class="ftabs">
            <button class="ftab active" onclick="setFilter('all',this)">All</button>
            <button class="ftab" onclick="setFilter('blocked',this)">Blocked</button>
            <button class="ftab" onclick="setFilter('redacted',this)">Redacted</button>
            <button class="ftab" onclick="setFilter('flagged',this)">Flagged</button>
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
              </tr>
            </thead>
            <tbody id="prompts-body">
              <tr class="empty"><td colspan="5">No prompts intercepted yet</td></tr>
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
    <div>
      <div class="panel">
        <div class="panel-hd">
          <span class="panel-title">Detection Rules</span>
          <span class="panel-count" id="rules-count">0</span>
        </div>
        <div id="rules-list"></div>
      </div>
    </div>
  </div>

</main>

<script>
var currentFilter = 'all';
var currentPage   = 1;
var pageSize      = 25;
var openRow       = null;

function toggleTheme() {
  var html = document.documentElement;
  var next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  localStorage.setItem('pg-theme', next);
  document.getElementById('theme-btn').textContent = next === 'dark' ? '☀' : '☾';
}
(function(){
  var t = document.documentElement.getAttribute('data-theme');
  document.getElementById('theme-btn').textContent = t === 'dark' ? '☀' : '☾';
})();

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
  if (openRow !== null) {
    var old = document.getElementById('detail-'+openRow);
    if (old) old.remove();
    if (openRow === id) { openRow = null; return; }
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

  var detail = document.createElement('tr');
  detail.id = 'detail-'+id;
  detail.className = 'detail-row';
  detail.innerHTML = '<td colspan="5"><div class="detail-inner">' +
    banner + promptSection +
    '<div class="detail-section-lbl" style="margin-top:10px;margin-bottom:6px">Matched Rules</div>' +
    '<div class="match-list">'+matchHTML+'</div>' +
    '</div></td>';
  anchor.after(detail);
}

var lastTopId = null;

async function refresh() {
  try {
    var qs = '?page='+currentPage+'&per_page='+pageSize+(currentFilter !== 'all' ? '&status='+currentFilter : '');
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
    document.getElementById('tile-blocked').textContent  = stats.blocked  || 0;
    document.getElementById('tile-host').textContent     = stats.most_flagged_host || '—';
    document.getElementById('prompt-count').textContent  = total;

    // Pagination controls
    var start = (currentPage-1)*pageSize+1;
    var end   = Math.min(currentPage*pageSize, total);
    document.getElementById('pg-info').textContent = total === 0 ? '' : start+'-'+end+' of '+total;
    document.getElementById('pg-prev').disabled = currentPage <= 1;
    document.getElementById('pg-next').disabled = currentPage >= totalPages;

    var newTopId = prompts.length > 0 ? prompts[0].id : null;
    if (newTopId === lastTopId && currentPage > 1) return; // stable inner page — skip re-render
    lastTopId = newTopId;

    window._promptData = {};
    prompts.forEach(function(p){ window._promptData[p.id] = p; });
    var wasOpen = openRow;

    document.getElementById('prompts-body').innerHTML = prompts.length === 0
      ? '<tr class="empty"><td colspan="5">No prompts'+(currentFilter !== 'all' ? ' matching "'+currentFilter+'"' : '')+'</td></tr>'
      : prompts.map(function(p) {
          var rulesStr = (p.rules||[]).join(', ') || '—';
          return '<tr id="row-'+p.id+'" class="row-'+p.status+'" onclick="toggleDetail('+p.id+')">' +
            '<td class="mono muted">'+esc(p.time)+'</td>' +
            '<td>'+statusTag(p.status)+'</td>' +
            '<td style="font-weight:600">'+esc(p.host)+'</td>' +
            '<td class="mono muted">'+esc(p.path)+'</td>' +
            '<td style="color:var(--text-2)">'+esc(rulesStr)+'</td>' +
            '</tr>';
        }).join('');

    if (wasOpen !== null && window._promptData[wasOpen]) {
      openRow = null;
      toggleDetail(wasOpen);
    }
  } catch(e) {
    document.getElementById('meta').textContent = 'error: '+e.message;
  }
}

async function loadRules() {
  try {
    var rules = await fetch('/api/rules').then(function(r){ return r.json(); });
    document.getElementById('rules-count').textContent = rules.length;
    document.getElementById('rules-list').innerHTML = rules.map(function(r) {
      var isBlock = r.mode === 'block';
      var sevClass = 'sev-'+(r.severity||'low');
      return '<div class="rule-card '+sevClass+'">' +
        '<div class="rule-top">' +
          '<div class="rule-info">' +
            '<div class="rule-name">'+esc(r.name)+'</div>' +
            '<div class="rule-desc">'+esc(r.description)+'</div>' +
          '</div>' +
          '<div class="seg" id="seg-'+esc(r.id)+'">' +
            '<button class="seg-btn '+(isBlock?'':'seg-active-track')+'" onclick="setMode(\''+esc(r.id)+'\',\'track\',this)">Track</button>' +
            '<button class="seg-btn '+(isBlock?'seg-active-block':'')+'" onclick="setMode(\''+esc(r.id)+'\',\'block\',this)">Block</button>' +
          '</div>' +
        '</div>' +
        '<div class="rule-foot">'+sevTag(r.severity)+'</div>' +
        '</div>';
    }).join('');
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

refresh();
loadRules();
setInterval(refresh, 3000);

function toggleExport() {
  var p = document.getElementById('export-panel');
  p.style.display = p.style.display === 'none' ? 'block' : 'none';
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
