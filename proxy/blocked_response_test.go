package proxy

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

// captureBlockedResponse runs writer on one end of a pipe and returns the
// HTTP response read off the other end.
func captureBlockedResponse(t *testing.T, writer func(net.Conn)) (*http.Response, []byte) {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		writer(server)
		server.Close()
		close(done)
	}()
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	<-done
	return resp, body
}

func TestWriteBlockedResponsesAPI_NonStreaming(t *testing.T) {
	const msg = "blocked: contains SSN"
	resp, body := captureBlockedResponse(t, func(c net.Conn) {
		writeBlockedResponsesAPI(c, msg, false)
	})

	if resp.StatusCode != 200 {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type: got %q want application/json", ct)
	}

	var parsed struct {
		ID     string `json:"id"`
		Object string `json:"object"`
		Status string `json:"status"`
		Output []struct {
			Type    string `json:"type"`
			Role    string `json:"role"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, body)
	}
	if parsed.Object != "response" {
		t.Errorf("object: got %q want response", parsed.Object)
	}
	if parsed.Status != "completed" {
		t.Errorf("status: got %q want completed", parsed.Status)
	}
	if len(parsed.Output) != 1 || parsed.Output[0].Type != "message" {
		t.Fatalf("expected single message output, got %+v", parsed.Output)
	}
	if len(parsed.Output[0].Content) != 1 || parsed.Output[0].Content[0].Type != "output_text" {
		t.Fatalf("expected single output_text content, got %+v", parsed.Output[0].Content)
	}
	if got := parsed.Output[0].Content[0].Text; got != msg {
		t.Errorf("text: got %q want %q", got, msg)
	}
}

func TestWriteBlockedResponsesAPI_Streaming(t *testing.T) {
	const msg = "blocked: contains SSN"
	resp, body := captureBlockedResponse(t, func(c net.Conn) {
		writeBlockedResponsesAPI(c, msg, true)
	})

	if resp.StatusCode != 200 {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type: got %q want text/event-stream", ct)
	}

	requiredEvents := []string{
		"event: response.created",
		"event: response.output_item.added",
		"event: response.content_part.added",
		"event: response.output_text.delta",
		"event: response.output_text.done",
		"event: response.content_part.done",
		"event: response.output_item.done",
		"event: response.completed",
	}
	for _, ev := range requiredEvents {
		if !strings.Contains(string(body), ev) {
			t.Errorf("streaming body missing %q\nbody: %s", ev, body)
		}
	}

	// Parse each `data: …` line as JSON to confirm well-formed payloads.
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		var any interface{}
		if err := json.Unmarshal([]byte(payload), &any); err != nil {
			t.Errorf("malformed data payload: %v\n%s", err, payload)
		}
	}

	// The text payload must round-trip through the delta event verbatim.
	if !strings.Contains(string(body), msg) {
		t.Errorf("streaming body does not contain assistant message %q", msg)
	}
}

func TestWriteBlockedResponse_RoutesResponsesPath(t *testing.T) {
	// /responses path should produce a `response` envelope, not a chat.completion.
	resp, body := captureBlockedResponse(t, func(c net.Conn) {
		writeBlockedResponse(c, "blocked", false, "/responses")
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"object":"response"`) {
		t.Errorf("expected response envelope for /responses path, got: %s", body)
	}
	if strings.Contains(string(body), `"object":"chat.completion"`) {
		t.Errorf("/responses path leaked into chat.completion branch: %s", body)
	}
}
