// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU Affero General Public License, Version 3 (AGPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/agpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGeneratedCallbackRetriesKeepEventID(t *testing.T) {
	for _, tool := range []string{"curl", "jq", "od"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	var mu sync.Mutex
	var ids []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ids = append(ids, r.Header.Get("X-Callback-Event-ID"))
		first := len(ids) == 1
		mu.Unlock()
		if r.Header.Get("X-Callback-Secret") != "test-secret" {
			t.Error("missing callback secret")
		}
		if first {
			time.Sleep(2 * time.Second)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	content, err := BuildFail2banActionConfig(server.URL, "test", "test-secret")
	if err != nil {
		t.Fatal(err)
	}
	_, command, ok := strings.Cut(content, "actionunban = ")
	if !ok {
		t.Fatal("missing actionunban")
	}
	command, _, _ = strings.Cut(command, "\n\n")
	command = strings.NewReplacer("<ip>", "192.0.2.1", "<name>", "sshd", "<fq-hostname>", "test-host", "%%", "%").Replace(command)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started := time.Now()
	if output, err := exec.CommandContext(ctx, "sh", "-c", command).CombinedOutput(); err != nil {
		t.Fatalf("callback failed: %v %s", err, output)
	}
	// fail2ban runs actions synchronously per ticket, so the action must hand off the retries.
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("action blocked for %v; a slow UI would delay the next ban", elapsed)
	}
	deadline := time.Now().Add(8 * time.Second)
	for {
		mu.Lock()
		n := len(ids)
		mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(ids) != 2 || len(ids[0]) != 32 || ids[0] != ids[1] {
		t.Fatalf("retry event IDs: %v", ids)
	}
}

func TestGeneratedBanCallbackCarriesLargeLogs(t *testing.T) {
	for _, tool := range []string{"curl", "jq", "od", "tac"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	bodies := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logFile := filepath.Join(t.TempDir(), "access.log")
	line := `{"client":"192.0.2.1","request":"GET /` + strings.Repeat("a", 900) + `","status":404}` + "\n"
	if err := os.WriteFile(logFile, []byte(strings.Repeat(line, 200)), 0o644); err != nil {
		t.Fatal(err)
	}
	content, err := BuildFail2banActionConfig(server.URL, "test", "test-secret")
	if err != nil {
		t.Fatal(err)
	}
	_, command, ok := strings.Cut(content, "actionban = ")
	if !ok {
		t.Fatal("missing actionban")
	}
	command, _, _ = strings.Cut(command, "\n\n")
	command = strings.NewReplacer("<ip>", "192.0.2.1", "<name>", "nginx", "<fq-hostname>", "test-host",
		"<failures>", "5", "<logpath>", logFile, "<grepopts>", "-m 200", "%%", "%").Replace(command)
	if output, err := exec.Command("sh", "-c", command).CombinedOutput(); err != nil {
		t.Fatalf("ban action failed: %v %s", err, output)
	}

	select {
	case body := <-bodies:
		var event struct{ IP, Jail, Logs string }
		if err := json.Unmarshal(body, &event); err != nil {
			t.Fatalf("ban callback body is not JSON (%d bytes): %v", len(body), err)
		}
		if event.IP != "192.0.2.1" || event.Jail != "nginx" {
			t.Fatalf("ban callback identity = %s/%s", event.IP, event.Jail)
		}
		if len(event.Logs) < 128<<10 {
			t.Fatalf("ban callback carried %d bytes of logs, want all 200 lines", len(event.Logs))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ban callback never arrived")
	}
}
