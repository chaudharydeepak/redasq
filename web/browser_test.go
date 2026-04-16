package web_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/chaudharydeepak/prompt-guard/inspector"
	"github.com/chaudharydeepak/prompt-guard/store"
	"github.com/chaudharydeepak/prompt-guard/web"
)

// newTestServer starts a real dashboard server backed by a temp SQLite DB.
func newTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	eng := inspector.New()
	srv := httptest.NewServer(web.NewHandler(db, eng, filepath.Join(dir, "rules.json")))
	t.Cleanup(func() { srv.Close() })
	return srv, db
}

// newChrome returns a chromedp context pointed at the real Chrome installation.
func newChrome(t *testing.T) context.Context {
	t.Helper()
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", "new"),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-extensions", true),
	)
	// Prefer explicitly known Chrome paths over chromedp auto-discovery,
	// which can pick up incompatible Chromium builds on CI runners.
	for _, p := range []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", // macOS
		"/usr/bin/google-chrome",                                        // Linux (google-chrome-stable)
		"/usr/bin/google-chrome-stable",                                 // Linux alt
	} {
		if _, err := os.Stat(p); err == nil {
			opts = append(opts, chromedp.ExecPath(p))
			break
		}
	}
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancelCtx := chromedp.NewContext(allocCtx)
	t.Cleanup(func() { cancelCtx(); cancelAlloc() })
	return ctx
}

// TestDashboardLoads checks the page renders all key structural elements.
func TestDashboardLoads(t *testing.T) {
	srv, _ := newTestServer(t)
	ctx, cancel := context.WithTimeout(newChrome(t), 20*time.Second)
	defer cancel()

	var tileText, tableHeader string
	err := chromedp.Run(ctx,
		chromedp.Navigate(srv.URL),
		chromedp.WaitVisible(`#tile-total`, chromedp.ByID),
		chromedp.Text(`#tile-total`, &tileText, chromedp.ByID),
		chromedp.WaitVisible(`.pg-tbl thead`, chromedp.ByQuery),
		chromedp.Text(`.pg-tbl thead`, &tableHeader, chromedp.ByQuery),
	)
	if err != nil {
		t.Fatalf("dashboard load: %v", err)
	}
	if tileText == "" {
		t.Error("tile-total is empty")
	}
	for _, col := range []string{"Status", "Host", "Latency", "Model"} {
		if len(tableHeader) == 0 {
			t.Errorf("table header missing column: %s", col)
		}
	}
}

// TestRulesPanelToggle checks collapse and expand of the detection rules panel.
func TestRulesPanelToggle(t *testing.T) {
	srv, _ := newTestServer(t)
	ctx, cancel := context.WithTimeout(newChrome(t), 20*time.Second)
	defer cancel()

	var innerVisible, stripVisible bool
	err := chromedp.Run(ctx,
		chromedp.Navigate(srv.URL),
		chromedp.WaitVisible(`.rules-toggle-btn`, chromedp.ByQuery),

		// Panel starts expanded — inner content visible, collapsed strip hidden.
		chromedp.Evaluate(`getComputedStyle(document.querySelector('.rules-panel-inner')).display !== 'none'`, &innerVisible),
		chromedp.Evaluate(`getComputedStyle(document.querySelector('.rules-collapsed-strip')).display === 'none'`, &stripVisible),
	)
	if err != nil {
		t.Fatalf("rules panel initial state: %v", err)
	}
	if !innerVisible {
		t.Error("rules panel inner should be visible when expanded")
	}
	if !stripVisible {
		t.Error("collapsed strip should be hidden when expanded")
	}

	// Click the toggle button to collapse.
	var afterInnerHidden, afterStripVisible bool
	err = chromedp.Run(ctx,
		chromedp.Click(`.rules-toggle-btn`, chromedp.ByQuery),
		chromedp.Sleep(300*time.Millisecond), // allow CSS transition
		chromedp.Evaluate(`getComputedStyle(document.querySelector('.rules-panel-inner')).display === 'none'`, &afterInnerHidden),
		chromedp.Evaluate(`getComputedStyle(document.querySelector('.rules-collapsed-strip')).display !== 'none'`, &afterStripVisible),
	)
	if err != nil {
		t.Fatalf("rules panel collapse: %v", err)
	}
	if !afterInnerHidden {
		t.Error("rules panel inner should be hidden after collapse")
	}
	if !afterStripVisible {
		t.Error("collapsed strip should be visible after collapse")
	}

	// Click collapsed strip to expand again.
	var expandedAgain bool
	err = chromedp.Run(ctx,
		chromedp.Click(`.rules-collapsed-strip`, chromedp.ByQuery),
		chromedp.Sleep(300*time.Millisecond),
		chromedp.Evaluate(`getComputedStyle(document.querySelector('.rules-panel-inner')).display !== 'none'`, &expandedAgain),
	)
	if err != nil {
		t.Fatalf("rules panel re-expand: %v", err)
	}
	if !expandedAgain {
		t.Error("rules panel inner should be visible after re-expand")
	}
}

// TestFilterTabsChangeState checks that clicking filter tabs updates the active state.
func TestFilterTabsChangeState(t *testing.T) {
	srv, _ := newTestServer(t)
	ctx, cancel := context.WithTimeout(newChrome(t), 20*time.Second)
	defer cancel()

	var blockedActive bool
	err := chromedp.Run(ctx,
		chromedp.Navigate(srv.URL),
		chromedp.WaitVisible(`.ftabs .ftab`, chromedp.ByQuery),
		// Click the "Blocked" tab (second button inside .ftabs).
		chromedp.Evaluate(`document.querySelectorAll('.ftabs .ftab')[1].click()`, nil),
		chromedp.Sleep(200*time.Millisecond),
		// The clicked tab should now have the active class.
		chromedp.Evaluate(`document.querySelectorAll('.ftabs .ftab')[1].classList.contains('active')`, &blockedActive),
	)
	if err != nil {
		t.Fatalf("filter tab click: %v", err)
	}
	if !blockedActive {
		t.Error("blocked filter tab should be active after click")
	}
}

// TestPromptRowExpand seeds a prompt then checks clicking the row shows a detail section.
func TestPromptRowExpand(t *testing.T) {
	srv, db := newTestServer(t)
	ctx, cancel := context.WithTimeout(newChrome(t), 20*time.Second)
	defer cancel()

	// Seed one prompt.
	_, err := db.SavePrompt(store.Prompt{
		Timestamp: time.Now(),
		Host:      "api.anthropic.com",
		Path:      "/v1/messages",
		Prompt:    "hello world",
		Status:    store.StatusClean,
		Model:     "claude-sonnet-4-6",
	})
	if err != nil {
		t.Fatalf("SavePrompt: %v", err)
	}

	var detailVisible bool
	err = chromedp.Run(ctx,
		chromedp.Navigate(srv.URL),
		chromedp.WaitVisible(`#prompts-body tr`, chromedp.ByQuery),
		chromedp.Click(`#prompts-body tr`, chromedp.ByQuery),
		chromedp.Sleep(300*time.Millisecond),
		chromedp.Evaluate(`document.querySelector('.detail-row') !== null`, &detailVisible),
	)
	if err != nil {
		t.Fatalf("prompt row expand: %v", err)
	}
	if !detailVisible {
		t.Error("detail row should appear after clicking a prompt row")
	}
}

// TestModelLatencyTable seeds prompts with model+duration and checks the latency table appears.
func TestModelLatencyTable(t *testing.T) {
	srv, db := newTestServer(t)
	ctx, cancel := context.WithTimeout(newChrome(t), 20*time.Second)
	defer cancel()

	// Seed several prompts with model and TTFB.
	for i := 0; i < 5; i++ {
		id, _ := db.SavePrompt(store.Prompt{
			Timestamp: time.Now(),
			Host:      "api.anthropic.com",
			Path:      "/v1/messages",
			Prompt:    "test",
			Status:    store.StatusClean,
			Model:     "claude-sonnet-4-6",
		})
		db.UpdateDuration(id, int64(1000+i*200))
	}

	var rowVisible bool
	var tableText string
	err := chromedp.Run(ctx,
		chromedp.Navigate(srv.URL),
		// Model latency table row should appear after refreshModelStats fires on load.
		chromedp.WaitVisible(`#model-latency-row`, chromedp.ByID),
		chromedp.Evaluate(`document.getElementById('model-latency-row').style.display !== 'none'`, &rowVisible),
		chromedp.Text(`#model-latency-body`, &tableText, chromedp.ByID),
	)
	if err != nil {
		t.Fatalf("model latency table: %v", err)
	}
	if !rowVisible {
		t.Error("model latency row should be visible when data exists")
	}
	if tableText == "" {
		t.Error("model latency table body should contain text")
	}
}
