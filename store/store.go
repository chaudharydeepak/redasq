package store

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/chaudharydeepak/prompt-guard/inspector"
	_ "modernc.org/sqlite"
)

type Status string

const (
	StatusClean     Status = "clean"
	StatusFlagged   Status = "flagged"
	StatusRedacted  Status = "redacted"
	StatusBlocked   Status = "blocked"
	StatusTelemetry Status = "telemetry"
)

// Prompt is an intercepted prompt with its inspection outcome.
type Prompt struct {
	ID             int64
	Timestamp      time.Time
	Host           string
	Path           string
	Prompt         string
	RedactedPrompt string
	Status         Status
	Matches        []inspector.Match
	DurationMS     int64
	AgentMode      bool
	InputTokens    int
	OutputTokens   int
	SessionID      string
	Client         string
	Model          string
	LLMResponse    string // stored when status=redacted; full text, no truncation
}

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	return s, s.migrate()
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS rule_overrides (
			rule_id TEXT PRIMARY KEY,
			mode    TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS prompts (
			id               INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp        INTEGER NOT NULL,
			host             TEXT    NOT NULL,
			path             TEXT    NOT NULL,
			prompt           TEXT    NOT NULL,
			status           TEXT    NOT NULL DEFAULT 'clean',
			matches          TEXT    NOT NULL DEFAULT '[]',
			redacted_prompt  TEXT    NOT NULL DEFAULT '',
			duration_ms      INTEGER NOT NULL DEFAULT 0,
			agent_mode       INTEGER NOT NULL DEFAULT 0,
			input_tokens     INTEGER NOT NULL DEFAULT 0,
			output_tokens    INTEGER NOT NULL DEFAULT 0,
			session_id       TEXT    NOT NULL DEFAULT '',
			client           TEXT    NOT NULL DEFAULT '',
			model            TEXT    NOT NULL DEFAULT '',
			llm_response     TEXT    NOT NULL DEFAULT ''
		);
		CREATE TABLE IF NOT EXISTS settings (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_ts     ON prompts(timestamp);
		CREATE INDEX IF NOT EXISTS idx_status ON prompts(status);
	`)
	if err != nil {
		return err
	}
	// Add columns to existing databases that predate these migrations.
	s.db.Exec(`ALTER TABLE prompts ADD COLUMN redacted_prompt TEXT NOT NULL DEFAULT ''`)
	s.db.Exec(`ALTER TABLE prompts ADD COLUMN duration_ms INTEGER NOT NULL DEFAULT 0`)
	s.db.Exec(`ALTER TABLE prompts ADD COLUMN agent_mode INTEGER NOT NULL DEFAULT 0`)
	s.db.Exec(`ALTER TABLE prompts ADD COLUMN input_tokens INTEGER NOT NULL DEFAULT 0`)
	s.db.Exec(`ALTER TABLE prompts ADD COLUMN output_tokens INTEGER NOT NULL DEFAULT 0`)
	s.db.Exec(`ALTER TABLE prompts ADD COLUMN session_id TEXT NOT NULL DEFAULT ''`)
	s.db.Exec(`ALTER TABLE prompts ADD COLUMN client TEXT NOT NULL DEFAULT ''`)
	s.db.Exec(`ALTER TABLE prompts ADD COLUMN model TEXT NOT NULL DEFAULT ''`)
	s.db.Exec(`ALTER TABLE prompts ADD COLUMN llm_response TEXT NOT NULL DEFAULT ''`)
	return nil
}

// GetSetting returns a persisted setting value, or the given default if not set.
func (s *Store) GetSetting(key, defaultVal string) string {
	var val string
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&val); err != nil {
		return defaultVal
	}
	return val
}

// SetSetting persists a key-value setting.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *Store) SavePrompt(p Prompt) (int64, error) {
	b, _ := json.Marshal(p.Matches)
	if b == nil {
		b = []byte("[]")
	}
	agentModeInt := 0
	if p.AgentMode {
		agentModeInt = 1
	}
	res, err := s.db.Exec(
		`INSERT INTO prompts (timestamp, host, path, prompt, status, matches, redacted_prompt, duration_ms, agent_mode, session_id, client, model) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.Timestamp.Unix(), p.Host, p.Path, p.Prompt, string(p.Status), string(b), p.RedactedPrompt, p.DurationMS, agentModeInt, p.SessionID, p.Client, p.Model,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateDuration(id, durationMS int64) error {
	_, err := s.db.Exec(`UPDATE prompts SET duration_ms=? WHERE id=?`, durationMS, id)
	return err
}

func (s *Store) UpdateTokens(id int64, inputTokens, outputTokens int) error {
	_, err := s.db.Exec(`UPDATE prompts SET input_tokens=?, output_tokens=? WHERE id=?`, inputTokens, outputTokens, id)
	return err
}

// UpdateLLMResponse stores the LLM response for a redacted prompt (compliance audit).
func (s *Store) UpdateLLMResponse(id int64, response string) error {
	_, err := s.db.Exec(`UPDATE prompts SET llm_response=? WHERE id=?`, response, id)
	return err
}

func (s *Store) CountPrompts(statusFilter, search string) (int, error) {
	var n int
	var err error
	like := "%" + search + "%"
	switch {
	case (statusFilter == "" || statusFilter == "all") && search == "":
		err = s.db.QueryRow(`SELECT COUNT(*) FROM prompts`).Scan(&n)
	case statusFilter == "" || statusFilter == "all":
		err = s.db.QueryRow(
			`SELECT COUNT(*) FROM prompts WHERE prompt LIKE ? OR host LIKE ? OR client LIKE ? OR session_id LIKE ?`,
			like, like, like, like).Scan(&n)
	case search == "":
		err = s.db.QueryRow(`SELECT COUNT(*) FROM prompts WHERE status = ?`, statusFilter).Scan(&n)
	default:
		err = s.db.QueryRow(
			`SELECT COUNT(*) FROM prompts WHERE status = ? AND (prompt LIKE ? OR host LIKE ? OR client LIKE ? OR session_id LIKE ?)`,
			statusFilter, like, like, like, like).Scan(&n)
	}
	return n, err
}

func (s *Store) ListPrompts(statusFilter, search string, limit, offset int) ([]Prompt, error) {
	const sel = `SELECT id, timestamp, host, path, prompt, status, matches, redacted_prompt, duration_ms, agent_mode, input_tokens, output_tokens, session_id, client, model, llm_response FROM prompts`
	like := "%" + search + "%"
	var (
		rows *sql.Rows
		err  error
	)
	switch {
	case (statusFilter == "" || statusFilter == "all") && search == "":
		rows, err = s.db.Query(sel+` ORDER BY timestamp DESC LIMIT ? OFFSET ?`, limit, offset)
	case statusFilter == "" || statusFilter == "all":
		rows, err = s.db.Query(sel+` WHERE prompt LIKE ? OR host LIKE ? OR client LIKE ? OR session_id LIKE ? ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
			like, like, like, like, limit, offset)
	case search == "":
		rows, err = s.db.Query(sel+` WHERE status = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?`, statusFilter, limit, offset)
	default:
		rows, err = s.db.Query(sel+` WHERE status = ? AND (prompt LIKE ? OR host LIKE ? OR client LIKE ? OR session_id LIKE ?) ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
			statusFilter, like, like, like, like, limit, offset)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPrompts(rows)
}

func (s *Store) GetPrompt(id int64) (*Prompt, error) {
	row := s.db.QueryRow(
		`SELECT id, timestamp, host, path, prompt, status, matches, redacted_prompt, duration_ms, agent_mode, input_tokens, output_tokens, session_id, client, model, llm_response FROM prompts WHERE id = ?`, id,
	)
	var p Prompt
	var ts int64
	var matchJSON string
	var agentModeInt int
	if err := row.Scan(&p.ID, &ts, &p.Host, &p.Path, &p.Prompt, &p.Status, &matchJSON, &p.RedactedPrompt, &p.DurationMS, &agentModeInt, &p.InputTokens, &p.OutputTokens, &p.SessionID, &p.Client, &p.Model, &p.LLMResponse); err != nil {
		return nil, err
	}
	p.Timestamp = time.Unix(ts, 0)
	p.AgentMode = agentModeInt == 1
	_ = json.Unmarshal([]byte(matchJSON), &p.Matches)
	return &p, nil
}

func scanPrompts(rows *sql.Rows) ([]Prompt, error) {
	var out []Prompt
	for rows.Next() {
		var p Prompt
		var ts int64
		var matchJSON string
		var agentModeInt int
		if err := rows.Scan(&p.ID, &ts, &p.Host, &p.Path, &p.Prompt, &p.Status, &matchJSON, &p.RedactedPrompt, &p.DurationMS, &agentModeInt, &p.InputTokens, &p.OutputTokens, &p.SessionID, &p.Client, &p.Model, &p.LLMResponse); err != nil {
			return nil, err
		}
		p.Timestamp = time.Unix(ts, 0)
		p.AgentMode = agentModeInt == 1
		_ = json.Unmarshal([]byte(matchJSON), &p.Matches)
		out = append(out, p)
	}
	return out, rows.Err()
}

type Stats struct {
	Total           int    `json:"total"`
	Clean           int    `json:"clean"`
	Flagged         int    `json:"flagged"`
	Redacted        int    `json:"redacted"`
	Blocked         int    `json:"blocked"`
	Telemetry       int    `json:"telemetry"`
	MostFlaggedHost string `json:"most_flagged_host"`
	TotalInputTokens  int    `json:"total_input_tokens"`
	TotalOutputTokens int    `json:"total_output_tokens"`
}

func (s *Store) Stats() Stats {
	var st Stats
	s.db.QueryRow(`SELECT COUNT(*) FROM prompts`).Scan(&st.Total)
	s.db.QueryRow(`SELECT COUNT(*) FROM prompts WHERE status='clean'`).Scan(&st.Clean)
	s.db.QueryRow(`SELECT COUNT(*) FROM prompts WHERE status='flagged'`).Scan(&st.Flagged)
	s.db.QueryRow(`SELECT COUNT(*) FROM prompts WHERE status='redacted'`).Scan(&st.Redacted)
	s.db.QueryRow(`SELECT COUNT(*) FROM prompts WHERE status='blocked'`).Scan(&st.Blocked)
	s.db.QueryRow(`SELECT COUNT(*) FROM prompts WHERE status='telemetry'`).Scan(&st.Telemetry)
	s.db.QueryRow(
		`SELECT host FROM prompts WHERE status!='clean' AND status!='telemetry' GROUP BY host ORDER BY COUNT(*) DESC LIMIT 1`,
	).Scan(&st.MostFlaggedHost)
	s.db.QueryRow(`SELECT COALESCE(SUM(input_tokens),0) FROM prompts`).Scan(&st.TotalInputTokens)
	s.db.QueryRow(`SELECT COALESCE(SUM(output_tokens),0) FROM prompts`).Scan(&st.TotalOutputTokens)
	return st
}

// ModelStat holds latency percentiles for a single client+model combination.
type ModelStat struct {
	Client string `json:"client"`
	Model  string `json:"model"`
	P50MS  int64  `json:"p50_ms"`
	P95MS  int64  `json:"p95_ms"`
	P99MS  int64  `json:"p99_ms"`
	Sample int    `json:"sample"`
}

// ModelStats returns p50/p95/p99 TTFB per client+model from the last 50 completed requests each.
func (s *Store) ModelStats() ([]ModelStat, error) {
	rows, err := s.db.Query(`
		SELECT client, model, duration_ms
		FROM (
			SELECT client, model, duration_ms,
			       ROW_NUMBER() OVER (PARTITION BY client, model ORDER BY timestamp DESC) AS rn
			FROM prompts
			WHERE model != '' AND duration_ms > 0
		)
		WHERE rn <= 50
		ORDER BY client, model, duration_ms
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type groupKey struct{ client, model string }
	type group struct{ durations []int64 }
	groups := map[groupKey]*group{}
	var order []groupKey
	for rows.Next() {
		var client, model string
		var ms int64
		if err := rows.Scan(&client, &model, &ms); err != nil {
			return nil, err
		}
		k := groupKey{client, model}
		if _, ok := groups[k]; !ok {
			groups[k] = &group{}
			order = append(order, k)
		}
		groups[k].durations = append(groups[k].durations, ms)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]ModelStat, 0, len(order))
	for _, k := range order {
		d := groups[k].durations
		n := len(d)
		p50 := d[int(float64(n)*0.50)]
		p95 := d[min(int(float64(n)*0.95), n-1)]
		p99 := d[min(int(float64(n)*0.99), n-1)]
		out = append(out, ModelStat{Client: k.client, Model: k.model, P50MS: p50, P95MS: p95, P99MS: p99, Sample: n})
	}
	return out, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ExportPrompts returns prompts in chronological order within the given time range.
// Pass zero values to export all. Secrets are never exported — redacted text is used.
func (s *Store) ExportPrompts(from, to time.Time) ([]Prompt, error) {
	var rows *sql.Rows
	var err error
	const sel = `SELECT id, timestamp, host, path, prompt, status, matches, redacted_prompt, duration_ms, agent_mode, input_tokens, output_tokens, session_id, client, model, llm_response FROM prompts`
	switch {
	case !from.IsZero() && !to.IsZero():
		rows, err = s.db.Query(sel+` WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp ASC`, from.Unix(), to.Unix())
	case !from.IsZero():
		rows, err = s.db.Query(sel+` WHERE timestamp >= ? ORDER BY timestamp ASC`, from.Unix())
	case !to.IsZero():
		rows, err = s.db.Query(sel+` WHERE timestamp <= ? ORDER BY timestamp ASC`, to.Unix())
	default:
		rows, err = s.db.Query(sel + ` ORDER BY timestamp ASC`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPrompts(rows)
}

// DeleteAllPrompts removes all intercepted prompts from the store.
func (s *Store) DeleteAllPrompts() error {
	_, err := s.db.Exec(`DELETE FROM prompts`)
	return err
}

// SetRuleMode persists a rule mode override and returns it on next load.
func (s *Store) SetRuleMode(ruleID, mode string) error {
	_, err := s.db.Exec(
		`INSERT INTO rule_overrides (rule_id, mode) VALUES (?,?)
		 ON CONFLICT(rule_id) DO UPDATE SET mode=excluded.mode`,
		ruleID, mode,
	)
	return err
}

// LoadRuleOverrides returns all persisted rule mode overrides.
func (s *Store) LoadRuleOverrides() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT rule_id, mode FROM rule_overrides`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var id, mode string
		if err := rows.Scan(&id, &mode); err != nil {
			return nil, err
		}
		out[id] = mode
	}
	return out, rows.Err()
}
