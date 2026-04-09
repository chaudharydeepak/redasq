package inspector

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
)

// RuleConfig is the JSON shape for a custom rule in rules.json.
type RuleConfig struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Pattern     string `json:"pattern"`
	Severity    string `json:"severity"` // "high", "medium", "low"
	Mode        string `json:"mode"`     // "block", "track"
}

// Override adjusts an existing built-in rule without replacing it.
type Override struct {
	ID       string `json:"id"`
	Mode     string `json:"mode,omitempty"`
	Severity string `json:"severity,omitempty"`
}

// Config is the top-level structure of rules.json.
type Config struct {
	Overrides     []Override     `json:"overrides"`
	Rules         []RuleConfig   `json:"rules"`
	// ContextLimits maps a client prefix (e.g. "claude-cli", "copilot") to its
	// maximum context window in tokens. "default" is used as the fallback.
	ContextLimits map[string]int `json:"context_limits,omitempty"`
}

// LoadConfig reads rules.json from path. Returns an empty config if the file
// does not exist, so the proxy starts fine without one.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	for _, r := range cfg.Rules {
		if _, err := regexp.Compile(r.Pattern); err != nil {
			return nil, fmt.Errorf("rule %q: invalid pattern: %w", r.ID, err)
		}
	}
	return &cfg, nil
}

// UpdateConfigMode updates (or adds) a mode override for ruleID in rules.json,
// preserving all other content. Creates the file if it doesn't exist yet.
func UpdateConfigMode(path, ruleID, mode string) error {
	cfg, err := LoadConfig(path)
	if err != nil {
		return err
	}
	for i, o := range cfg.Overrides {
		if o.ID == ruleID {
			cfg.Overrides[i].Mode = mode
			return writeConfig(path, cfg)
		}
	}
	cfg.Overrides = append(cfg.Overrides, Override{ID: ruleID, Mode: mode})
	return writeConfig(path, cfg)
}

func writeConfig(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
