package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// dashboardURL matches the exact URL `mintrun watch` prints and the macOS menu bar app parses: a
// loopback address, and the token in the #fragment, which a browser never sends to a server.
var dashboardURL = regexp.MustCompile(`^http://127\.0\.0\.1:[0-9]+/#([A-Z2-7]+)$`)

// TestWatchDashboardBanner pins what `mintrun watch` prints. The dashboard answers any local user
// who finds the port, so the token in the printed URL is the only thing that keeps them out: a
// banner with no token, one whose token the server refuses, or one naming an address the dashboard
// does not serve would leave the operator (and the menu bar app, which reads this same line) locked
// out or, worse, handing the guard to whoever reads the URL.
func TestWatchDashboardBanner(t *testing.T) {
	home := t.TempDir()
	t.Setenv("MINTRUN_HOME", home)
	t.Setenv("MINTRUN_FILE_VAULT", "1")

	rt, err := bootRuntime()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()
	inW.Close()

	printed := false
	watch := func(out string) {
		if printed {
			return
		}
		const marker = "(dashboard: "
		i := strings.Index(out, marker)
		if i < 0 {
			return
		}
		url := out[i+len(marker):]
		j := strings.IndexAny(url, ")\n")
		if j < 0 {
			return // this read cut the banner short; the rest is on its way
		}
		printed = true
		defer cancel() // cmdWatch blocks until the context ends
		checkDashboardURL(t, url[:j])
	}

	r := capture(t, inR, watch, func() {
		cmdWatch(ctx, rt, []string{"-http", "127.0.0.1:0"})
	})
	if !printed {
		t.Fatalf("cmdWatch printed no dashboard banner: stdout=%q stderr=%q exited=%v code=%d", r.out, r.err, r.exited, r.code)
	}
}

// checkDashboardURL runs in capture's reader goroutine, so it reports with Errorf, never Fatalf.
func checkDashboardURL(t *testing.T, url string) {
	t.Helper()
	m := dashboardURL.FindStringSubmatch(url)
	if m == nil {
		t.Errorf("dashboard URL %q is not http://127.0.0.1:<port>/#<token>", url)
		return
	}
	token := m[1]
	addr := strings.TrimSuffix(strings.TrimPrefix(url, "http://"), "/#"+token)
	client := &http.Client{Timeout: 3 * time.Second}

	// The printed token is the one the guard accepts, and only with it does /api/ answer.
	status, body := watchAPIGet(t, client, addr, token)
	if status != http.StatusOK {
		t.Errorf("GET /api/state with the printed token %q: status=%d body=%q, want 200", token, status, body)
	} else {
		var state struct {
			Paused *bool `json:"paused"`
		}
		if err := json.Unmarshal([]byte(body), &state); err != nil || state.Paused == nil {
			t.Errorf("GET /api/state with the printed token: body=%q, want a JSON state object", body)
		}
	}
	if status, body := watchAPIGet(t, client, addr, ""); status != http.StatusForbidden {
		t.Errorf("GET /api/state without a token: status=%d body=%q, want 403", status, body)
	}
	if status, body := watchAPIGet(t, client, addr, token+"x"); status != http.StatusForbidden {
		t.Errorf("GET /api/state with a wrong token: status=%d body=%q, want 403", status, body)
	}
}

// watchAPIGet is a bare GET of the dashboard API, with the loopback Host a real client sends.
func watchAPIGet(t *testing.T, client *http.Client, addr, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/api/state", nil)
	if err != nil {
		t.Errorf("build request for %s: %v", addr, err)
		return 0, ""
	}
	req.Host = addr
	if token != "" {
		req.Header.Set("X-Mintrun-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("GET /api/state on %s: %v", addr, err)
		return 0, ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("read /api/state body: %v", err)
	}
	return resp.StatusCode, string(body)
}
