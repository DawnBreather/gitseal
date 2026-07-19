package client

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

const snapPub = "age1a55nf0y7wdeeafv026z0y2m6hdhkjuzmpvfpzakaqtw9zg4n6q5q9955mv"

func snapshotServer(t *testing.T, hits *int) *httptest.Server {
	body := `{"projects":{"` + snapPub + `":{` +
		`"project_id":338,` +
		`"env_cluster":{"prod":"example","staging":"staging"},` +
		`"env_min_level":{"prod":40,"staging":30},` +
		`"cluster_recipients":{"example":"age1G","staging":"age1S"}}}}`
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			*hits++
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

// FetchProjectConfig pulls the registry snapshot, finds the entry keyed by the
// repo pubkey, and returns the operational config (project_id, clusters,
// env_cluster, env_min_level) — the fields a v4 repo.yaml no longer carries.
func TestFetchProjectConfig_FromSnapshot(t *testing.T) {
	srv := snapshotServer(t, nil)
	defer srv.Close()

	cfg, err := FetchProjectConfig(srv.URL, snapPub, filepath.Join(t.TempDir(), "cache.json"))
	if err != nil {
		t.Fatalf("FetchProjectConfig: %v", err)
	}
	if cfg.ProjectID != 338 {
		t.Fatalf("project_id = %d", cfg.ProjectID)
	}
	if cfg.EnvCluster["prod"] != "example" || cfg.EnvCluster["staging"] != "staging" {
		t.Fatalf("env_cluster wrong: %+v", cfg.EnvCluster)
	}
	if cfg.EnvMinLevel["prod"] != 40 || cfg.EnvMinLevel["staging"] != 30 {
		t.Fatalf("env_min_level wrong: %+v", cfg.EnvMinLevel)
	}
	// the OLD-shape fixture back-compat-parses so each env's recipient is
	// its cluster's shared key (age1G for example, age1S for staging).
	if cfg.EnvRecipient["prod"] != "age1G" || cfg.EnvRecipient["staging"] != "age1S" {
		t.Fatalf("env recipients wrong: %+v", cfg.EnvRecipient)
	}
	// the pubkey is carried through as the recipient identity
	if cfg.Recipient != snapPub {
		t.Fatalf("recipient = %q", cfg.Recipient)
	}
}

// After a first successful fetch, the cache serves subsequent lookups WITHOUT
// hitting the network — so `seal` stays usable offline once primed.
func TestFetchProjectConfig_CacheIsOffline(t *testing.T) {
	hits := 0
	srv := snapshotServer(t, &hits)
	cachePath := filepath.Join(t.TempDir(), "cache.json")

	if _, err := FetchProjectConfig(srv.URL, snapPub, cachePath); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if hits != 1 {
		t.Fatalf("first fetch should hit the network once, got %d", hits)
	}
	// take the server down → cache must still resolve.
	srv.Close()
	cfg, err := FetchProjectConfig(srv.URL, snapPub, cachePath)
	if err != nil {
		t.Fatalf("cached fetch (server down) must succeed: %v", err)
	}
	if cfg.ProjectID != 338 {
		t.Fatalf("cached project_id = %d", cfg.ProjectID)
	}
}

// An unknown pubkey (not in the snapshot) is an error — fail closed, never a
// zero-value config that would seal to nothing.
func TestFetchProjectConfig_UnknownPubkey(t *testing.T) {
	srv := snapshotServer(t, nil)
	defer srv.Close()
	if _, err := FetchProjectConfig(srv.URL, "age1unknown", filepath.Join(t.TempDir(), "c.json")); err == nil {
		t.Fatal("unknown pubkey must fail (not in snapshot)")
	}
}
