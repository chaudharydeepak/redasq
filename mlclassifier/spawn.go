package mlclassifier

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// Config controls how Spawn locates and launches llama-server.
type Config struct {
	Binary  string // path to llama-server binary; falls back to PATH lookup of DefaultBinary
	Model   string // path to GGUF model file (required)
	Port    int    // loopback port to bind (default: DefaultPort)
	Threads int    // -t flag for llama-server (default: 8)
	Ctx     int    // -c flag, context window (default: 2048)
	LogPath string // where to redirect stdout/stderr (default: $TMPDIR/redasq-mlclassifier.log)
}

func (c *Config) defaults() {
	if c.Binary == "" {
		c.Binary = DefaultBinary
	}
	if c.Port == 0 {
		c.Port = DefaultPort
	}
	if c.Threads == 0 {
		c.Threads = 8
	}
	if c.Ctx == 0 {
		c.Ctx = 2048
	}
	if c.LogPath == "" {
		c.LogPath = filepath.Join(os.TempDir(), "redasq-mlclassifier.log")
	}
}

// Spawned wraps a managed llama-server child process.
type Spawned struct {
	cmd     *exec.Cmd
	URL     string
	Model   string
	LogPath string
}

// Spawn launches llama-server as a child and waits for /health to respond
// within readyTimeout. On success, returns a Spawned that the caller is
// responsible for Stop()ing on shutdown.
//
// Returns an error if the binary or model is missing, or the server doesn't
// become ready in time. Missing-binary and missing-model are common config
// errors — callers should treat them as "ML disabled" rather than fatal.
func Spawn(ctx context.Context, cfg Config, readyTimeout time.Duration) (*Spawned, error) {
	cfg.defaults()
	if cfg.Model == "" {
		return nil, errors.New("mlclassifier: model path required")
	}
	if _, err := os.Stat(cfg.Model); err != nil {
		return nil, fmt.Errorf("mlclassifier: model not found at %s: %w", cfg.Model, err)
	}

	binPath := cfg.Binary
	if filepath.IsAbs(binPath) {
		if _, err := os.Stat(binPath); err != nil {
			return nil, fmt.Errorf("mlclassifier: binary not found at %s: %w", binPath, err)
		}
	} else {
		resolved, err := exec.LookPath(binPath)
		if err != nil {
			return nil, fmt.Errorf("mlclassifier: binary %q not in PATH: %w", binPath, err)
		}
		binPath = resolved
	}

	args := []string{
		"-m", cfg.Model,
		"--host", "127.0.0.1",
		"--port", strconv.Itoa(cfg.Port),
		"-c", strconv.Itoa(cfg.Ctx),
		"-t", strconv.Itoa(cfg.Threads),
		"--log-disable",
	}

	cmd := exec.Command(binPath, args...)
	logFile, err := os.Create(cfg.LogPath)
	if err == nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("mlclassifier: start: %w", err)
	}

	s := &Spawned{
		cmd:     cmd,
		URL:     fmt.Sprintf("http://127.0.0.1:%d", cfg.Port),
		Model:   filepath.Base(cfg.Model),
		LogPath: cfg.LogPath,
	}

	client := New(s.URL)
	deadline := time.Now().Add(readyTimeout)
	for time.Now().Before(deadline) {
		hctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		err := client.Health(hctx)
		cancel()
		if err == nil {
			return s, nil
		}
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	_ = cmd.Process.Kill()
	return nil, fmt.Errorf("mlclassifier: server not ready after %s (logs: %s)", readyTimeout, cfg.LogPath)
}

// Stop sends SIGINT to the child and waits up to 5s for it to exit. Falls
// back to SIGKILL on timeout.
func (s *Spawned) Stop() error {
	if s == nil || s.cmd == nil || s.cmd.Process == nil {
		return nil
	}
	_ = s.cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
		return s.cmd.Process.Kill()
	}
}
