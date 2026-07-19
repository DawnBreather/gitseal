package broker

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// --- broker registry + snapshot (Stage C) ----------------------------
//
// The broker is the AUTHORITY for the project registry (pubkey → project config)
// and the user registry (ssh fingerprint → gitlab user_id). It distributes the
// PUBLIC project config as a JWKS-style cached snapshot (GET /v1/registry/snapshot)
// — recipients, env→cluster, env_min_level. NO private keys, NO user PII beyond
// fingerprints. Consumers (seal/verify) cache it; the materializer never calls it.

func TestRegistrySnapshot_PublicOnly(t *testing.T) {
	reg := &Registry{
		Projects: map[string]ProjectEntry{
			"age1projPUB": {
				ProjectID: 338,
				Envs: map[string]ProjectEnv{
					"prod":    {Cluster: "example", Namespace: "demoapp", MinLevel: 40, Recipient: "age1G"},
					"staging": {Cluster: "staging", Namespace: "demoapp", MinLevel: 30, Recipient: "age1S"},
				},
			},
		},
		Users: map[string]int64{"SHA256:abc": 87}, // must NOT appear in the snapshot
	}
	b := &Broker{Registry: reg}

	rr := httptest.NewRecorder()
	b.HandleRegistrySnapshot(rr, httptest.NewRequest("GET", "/v1/registry/snapshot", nil))
	if rr.Code != 200 {
		t.Fatalf("snapshot code = %d", rr.Code)
	}
	body := rr.Body.String()
	// the project config is present
	var snap RegistrySnapshot
	if err := json.Unmarshal([]byte(body), &snap); err != nil {
		t.Fatalf("snapshot not valid json: %v", err)
	}
	p, ok := snap.Projects["age1projPUB"]
	if !ok || p.ProjectID != 338 || p.Envs["prod"].Cluster != "example" || p.Envs["prod"].MinLevel != 40 {
		t.Fatalf("project config missing/wrong in snapshot: %+v", snap)
	}
	if p.Envs["prod"].Recipient != "age1G" || p.Envs["staging"].Recipient != "age1S" {
		t.Fatalf("per-env recipients missing in snapshot")
	}
	// user registry must NOT leak into the snapshot (no fingerprints, no user_ids)
	if containsAny(body, "SHA256:abc", "\"users\"", "87") {
		t.Fatalf("snapshot leaked the user registry: %s", body)
	}
}

// A project pubkey resolves to its config; an unknown pubkey → not found.
func TestRegistry_ResolveProject(t *testing.T) {
	reg := &Registry{Projects: map[string]ProjectEntry{"age1p": {ProjectID: 338}}}
	if e, ok := reg.Project("age1p"); !ok || e.ProjectID != 338 {
		t.Fatal("known project must resolve")
	}
	if _, ok := reg.Project("age1nope"); ok {
		t.Fatal("unknown project must not resolve")
	}
}

// user registry resolves fingerprint → user_id.
func TestRegistry_ResolveUser(t *testing.T) {
	reg := &Registry{Users: map[string]int64{"SHA256:abc": 87}}
	if uid, ok := reg.User("SHA256:abc"); !ok || uid != 87 {
		t.Fatal("known user must resolve")
	}
	if _, ok := reg.User("SHA256:zzz"); ok {
		t.Fatal("unknown fingerprint must not resolve")
	}
}

var _ = http.MethodGet

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}
