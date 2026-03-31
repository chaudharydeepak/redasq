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
	StatusClean    Status = "clean"
	StatusFlagged  Status = "flagged"
	StatusRedacted Status = "redacted"
	StatusBlocked  Status = "blocked"
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
			redacted_prompt  TEXT    NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_ts     ON prompts(timestamp);
		CREATE INDEX IF NOT EXISTS idx_status ON prompts(status);
	`)
	if err != nil {
		return err
	}
	// Add redacted_prompt column to existing databases that predate this migration.
	s.db.Exec(`ALTER TABLE prompts ADD COLUMN redacted_prompt TEXT NOT NULL DEFAULT ''`)
	return nil
}

func (s *Store) SavePrompt(p Prompt) error {
	b, _ := json.Marshal(p.Matches)
	if b == nil {
		b = []byte("[]")
	}
	_, err := s.db.Exec(
		`INSERT INTO prompts (timestamp, host, path, prompt, status, matches, redacted_prompt) VALUES (?,?,?,?,?,?,?)`,
		p.Timestamp.Unix(), p.Host, p.Path, p.Prompt, string(p.Status), string(b), p.RedactedPrompt,
	)
	return err
}

func (s *Store) CountPrompts(statusFilter string) (int, error) {
	var n int
	var err error
	if statusFilter == "" || statusFilter == "all" {
		err = s.db.QueryRow(`SELECT COUNT(*) FROM prompts`).Scan(&n)
	} else {
		err = s.db.QueryRow(`SELECT COUNT(*) FROM prompts WHERE status = ?`, statusFilter).Scan(&n)
	}
	return n, err
}

func (s *Store) ListPrompts(statusFilter string, limit, offset int) ([]Prompt, error) {
	var rows *sql.Rows
	var err error
	if statusFilter == "" || statusFilter == "all" {
		rows, err = s.db.Query(
			`SELECT id, timestamp, host, path, prompt, status, matches, redacted_prompt
			 FROM prompts ORDER BY timestamp DESC LIMIT ? OFFSET ?`, limit, offset,
		)
	} else {
		rows, err = s.db.Query(
			`SELECT id, timestamp, host, path, prompt, status, matches, redacted_prompt
			 FROM prompts WHERE status = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
			statusFilter, limit, offset,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPrompts(rows)
}

func (s *Store) GetPrompt(id int64) (*Prompt, error) {
	row := s.db.QueryRow(
		`SELECT id, timestamp, host, path, prompt, status, matches, redacted_prompt FROM prompts WHERE id = ?`, id,
	)
	var p Prompt
	var ts int64
	var matchJSON string
	if err := row.Scan(&p.ID, &ts, &p.Host, &p.Path, &p.Prompt, &p.Status, &matchJSON, &p.RedactedPrompt); err != nil {
		return nil, err
	}
	p.Timestamp = time.Unix(ts, 0)
	_ = json.Unmarshal([]byte(matchJSON), &p.Matches)
	return &p, nil
}

func scanPrompts(rows *sql.Rows) ([]Prompt, error) {
	var out []Prompt
	for rows.Next() {
		var p Prompt
		var ts int64
		var matchJSON string
		if err := rows.Scan(&p.ID, &ts, &p.Host, &p.Path, &p.Prompt, &p.Status, &matchJSON, &p.RedactedPrompt); err != nil {
			return nil, err
		}
		p.Timestamp = time.Unix(ts, 0)
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
	MostFlaggedHost string `json:"most_flagged_host"`
}

func (s *Store) Stats() Stats {
	var st Stats
	s.db.QueryRow(`SELECT COUNT(*) FROM prompts`).Scan(&st.Total)
	s.db.QueryRow(`SELECT COUNT(*) FROM prompts WHERE status='clean'`).Scan(&st.Clean)
	s.db.QueryRow(`SELECT COUNT(*) FROM prompts WHERE status='flagged'`).Scan(&st.Flagged)
	s.db.QueryRow(`SELECT COUNT(*) FROM prompts WHERE status='redacted'`).Scan(&st.Redacted)
	s.db.QueryRow(`SELECT COUNT(*) FROM prompts WHERE status='blocked'`).Scan(&st.Blocked)
	s.db.QueryRow(
		`SELECT host FROM prompts WHERE status!='clean' GROUP BY host ORDER BY COUNT(*) DESC LIMIT 1`,
	).Scan(&st.MostFlaggedHost)
	return st
}

// ExportPrompts returns prompts in chronological order within the given time range.
// Pass zero values to export all. Secrets are never exported — redacted text is used.
func (s *Store) ExportPrompts(from, to time.Time) ([]Prompt, error) {
	var rows *sql.Rows
	var err error
	switch {
	case !from.IsZero() && !to.IsZero():
		rows, err = s.db.Query(
			`SELECT id, timestamp, host, path, prompt, status, matches, redacted_prompt
			 FROM prompts WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp ASC`,
			from.Unix(), to.Unix(),
		)
	case !from.IsZero():
		rows, err = s.db.Query(
			`SELECT id, timestamp, host, path, prompt, status, matches, redacted_prompt
			 FROM prompts WHERE timestamp >= ? ORDER BY timestamp ASC`,
			from.Unix(),
		)
	case !to.IsZero():
		rows, err = s.db.Query(
			`SELECT id, timestamp, host, path, prompt, status, matches, redacted_prompt
			 FROM prompts WHERE timestamp <= ? ORDER BY timestamp ASC`,
			to.Unix(),
		)
	default:
		rows, err = s.db.Query(
			`SELECT id, timestamp, host, path, prompt, status, matches, redacted_prompt
			 FROM prompts ORDER BY timestamp ASC`,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPrompts(rows)
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
