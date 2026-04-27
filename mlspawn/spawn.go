// Package mlspawn brings up the Python classifier sidecar as a child process
// of redasq, so users do not have to start a separate server. The sidecar dies
// when redasq exits (we own its lifecycle) and a missing venv degrades to
// ML-disabled with a clear one-line setup hint rather than a hard failure.
package mlspawn

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ErrNoVenv is returned when the Python venv cannot be located. Callers
// should treat this as "ML disabled" and continue without it.
var ErrNoVenv = errors.New("python venv not found")

// Sidecar is a running classifier child process.
type Sidecar struct {
	URL    string // POST /classify endpoint, e.g. http://127.0.0.1:8000/classify
	cmd    *exec.Cmd
	logF   *os.File
}

// Start launches the classifier sidecar and waits up to readyTimeout for its
// /health endpoint to return ok. The sidecar's stdout/stderr are redirected
// to logPath. Returns ErrNoVenv if the venv binary cannot be found.
//
// repoRoot is the directory that contains the ml/ package (typically the
// redasq working directory). venvPath may be absolute or relative to
// repoRoot; an empty value defaults to "eval/.venv".
func Start(repoRoot, venvPath string, port int, logPath string, readyTimeout time.Duration) (*Sidecar, error) {
	if venvPath == "" {
		venvPath = "eval/.venv"
	}
	if !filepath.IsAbs(venvPath) {
		venvPath = filepath.Join(repoRoot, venvPath)
	}
	pyBin := filepath.Join(venvPath, "bin", "python")
	if _, err := os.Stat(pyBin); err != nil {
		return nil, fmt.Errorf("%w at %s", ErrNoVenv, pyBin)
	}

	logF, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("open log: %w", err)
	}

	cmd := exec.Command(pyBin, "-m", "uvicorn",
		"ml.classifier_server:app",
		"--host", "127.0.0.1",
		"--port", fmt.Sprintf("%d", port),
		"--log-level", "warning",
	)
	cmd.Dir = repoRoot
	cmd.Stdout = logF
	cmd.Stderr = logF

	if err := cmd.Start(); err != nil {
		logF.Close()
		return nil, fmt.Errorf("start sidecar: %w", err)
	}

	healthURL := fmt.Sprintf("http://127.0.0.1:%d/health", port)
	classifyURL := fmt.Sprintf("http://127.0.0.1:%d/classify", port)

	if err := waitHealthy(cmd, healthURL, readyTimeout); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		logF.Close()
		tail, _ := tailFile(logPath, 20)
		return nil, fmt.Errorf("classifier not ready in %s: %v\n--- last log lines (%s) ---\n%s",
			readyTimeout, err, logPath, tail)
	}

	return &Sidecar{URL: classifyURL, cmd: cmd, logF: logF}, nil
}

// Stop sends SIGTERM and waits briefly, escalating to Kill on timeout.
func (s *Sidecar) Stop() {
	if s == nil || s.cmd == nil || s.cmd.Process == nil {
		return
	}
	_ = s.cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() { _ = s.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = s.cmd.Process.Kill()
		<-done
	}
	if s.logF != nil {
		s.logF.Close()
	}
}

// PID returns the sidecar's process ID, or 0 if not running.
func (s *Sidecar) PID() int {
	if s == nil || s.cmd == nil || s.cmd.Process == nil {
		return 0
	}
	return s.cmd.Process.Pid
}

// VenvSetupHint returns a single-line shell command that creates the venv
// and installs the classifier dependencies. Shown when ErrNoVenv is hit.
func VenvSetupHint(venvPath string) string {
	if venvPath == "" {
		venvPath = "eval/.venv"
	}
	return fmt.Sprintf("python3 -m venv %s && %s/bin/pip install -r ml/requirements.txt",
		venvPath, venvPath)
}

func waitHealthy(cmd *exec.Cmd, healthURL string, timeout time.Duration) error {
	client := &http.Client{Timeout: 1 * time.Second}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			return fmt.Errorf("sidecar exited: %s", cmd.ProcessState)
		}
		resp, err := client.Get(healthURL)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && strings.Contains(string(body), `"ok"`) {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("timeout")
}

func tailFile(path string, n int) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n"), nil
}
