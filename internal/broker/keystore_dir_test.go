package broker

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/dawnbreather/gitseal/internal/client"
	"github.com/dawnbreather/gitseal/internal/crypto"
)

// writeKey writes a valid <pid>.key.json into dir and returns nothing.
func writeKey(t *testing.T, dir string, pid int64) {
	t.Helper()
	kp, _ := crypto.GenerateRepoKey()
	kek, _ := crypto.GenerateKEK()
	wrapped, _ := crypto.WrapKey([]byte(kp.Identity), kek)
	data, _ := json.Marshal(client.NewKeyFile(pid, wrapped, kek))
	if err := os.WriteFile(filepath.Join(dir, client.KeyFileName(pid)), data, 0600); err != nil {
		t.Fatal(err)
	}
}

// LoadKeyStoreDir adapts client.LoadKeyDir into a broker *KeyStore + skipped list.
// A bad key file is skipped, not fatal (the SPOF kill): one repo down, not all.
func TestLoadKeyStoreDir_TolerantAndAdapts(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, 338)
	writeKey(t, dir, 412)
	os.WriteFile(filepath.Join(dir, "999.key.json"), []byte("{bad"), 0600)

	ks, skipped, err := LoadKeyStoreDir(dir)
	if err != nil {
		t.Fatalf("must not be fatal on one bad file: %v", err)
	}
	if len(ks.Identities) != 2 || ks.Identities[338] == "" || ks.Identities[412] == "" {
		t.Fatalf("both good keys must load: %+v", ks.Identities)
	}
	if len(skipped) != 1 {
		t.Fatalf("one file must be skipped, got %d", len(skipped))
	}
}

// /readyz is a POSITIVE assertion: 200 only when >=1 key is loaded; it exposes
// the Degraded (skipped) set so a silently-down repo is visible. This is the
// anti-silent-health invariant.
func TestReadyz_PositiveSignal(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, 338)
	os.WriteFile(filepath.Join(dir, "999.key.json"), []byte("{bad"), 0600)
	ks, skipped, err := LoadKeyStoreDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	b := &Broker{Keys: ks, Skipped: skipped}

	rr := httptest.NewRecorder()
	b.HandleReadyz(rr, httptest.NewRequest("GET", "/readyz", nil))
	if rr.Code != 200 {
		t.Fatalf("readyz with 1 key should be 200, got %d", rr.Code)
	}
	// the degraded (skipped) set must be surfaced in the body
	if body := rr.Body.String(); !containsAll(body, "999", "degraded") {
		t.Fatalf("readyz body should report the degraded key: %q", body)
	}
}

func TestReadyz_ZeroKeysIsNotReady(t *testing.T) {
	b := &Broker{Keys: &KeyStore{Identities: map[int64]string{}}}
	rr := httptest.NewRecorder()
	b.HandleReadyz(rr, httptest.NewRequest("GET", "/readyz", nil))
	if rr.Code == 200 {
		t.Fatal("readyz with ZERO keys must NOT be 200 (empty broker is not ready)")
	}
}

// healthz stays a pure liveness ping (process is up), independent of key state.
func TestHealthz_LivenessOnly(t *testing.T) {
	b := &Broker{Keys: &KeyStore{Identities: map[int64]string{}}}
	rr := httptest.NewRecorder()
	b.HandleHealthz(rr, httptest.NewRequest("GET", "/healthz", nil))
	if rr.Code != 200 {
		t.Fatalf("healthz is liveness-only, should be 200 even with zero keys, got %d", rr.Code)
	}
}

// Once draining, /readyz returns 503 even with keys loaded (endpoint drain), while
// /healthz stays 200 (the process is still alive and finishing in-flight work).
func TestReadyz_DrainingReturns503(t *testing.T) {
	b := &Broker{Keys: &KeyStore{Identities: map[int64]string{338: "id"}}}
	rr := httptest.NewRecorder()
	b.HandleReadyz(rr, httptest.NewRequest("GET", "/readyz", nil))
	if rr.Code != 200 {
		t.Fatalf("pre-drain readyz should be 200, got %d", rr.Code)
	}
	b.BeginDrain()
	rr = httptest.NewRecorder()
	b.HandleReadyz(rr, httptest.NewRequest("GET", "/readyz", nil))
	if rr.Code != 503 {
		t.Fatalf("draining readyz must be 503, got %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	b.HandleHealthz(rr, httptest.NewRequest("GET", "/healthz", nil))
	if rr.Code != 200 {
		t.Fatalf("healthz must stay 200 while draining, got %d", rr.Code)
	}
}

var _ = http.MethodGet

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
