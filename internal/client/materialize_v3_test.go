package client

import (
	"path/filepath"
	"testing"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// TestMaterializeV3_CryptoGate2 proves gate #2 holds for v3 WITHOUT a cluster label:
// a materializer wired to cluster S (staging identity) CANNOT build the prod section
// (sealed to G) — UnsealVerified fails, aborting the whole build (fail-closed). The
// staging section, sealed to S, builds fine. This is invariant #3: the gate is
// CRYPTO (decrypt-what-you-can), not a label lookup, so the materializer needs no
// registry/broker call.
func TestMaterializeV3_CryptoGate2(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey() // example (prod)
	s, _ := crypto.GenerateRepoKey() // staging
	path := filepath.Join(t.TempDir(), "auth.app.json")
	clusters := map[string]string{"example": g.Recipient, "staging": s.Recipient}
	envCluster := map[string]string{"prod": "example", "staging": "staging"}
	if _, err := SealBundleV2(path, human.Recipient, clusters, envCluster, 338, 30,
		map[string]map[string]string{"prod": {"DB": "prod-secret"}, "staging": {"DB": "stg-secret"}}); err != nil {
		t.Fatal(err)
	}
	b, _ := LoadBundle(path)
	if b.Version != BundleVersionV3 {
		t.Fatalf("want v3, got %q", b.Version)
	}

	// staging identity building the PROD section → decrypt fails (gate #2 via crypto).
	_, err := BuildSecretForBundle(b, "auth", MaterializeInput{
		Env: "prod", Namespace: "demoapp", Cluster: "staging", Identity: []byte(s.Identity), ProjectID: 338,
	})
	if err == nil {
		t.Fatal("SECURITY: staging identity built the prod section (gate #2 crypto cross-check failed)")
	}

	// example identity building the PROD section → succeeds.
	sec, err := BuildSecretForBundle(b, "auth", MaterializeInput{
		Env: "prod", Namespace: "demoapp", Cluster: "example", Identity: []byte(g.Identity), ProjectID: 338,
	})
	if err != nil {
		t.Fatalf("example identity must build the prod section: %v", err)
	}
	if string(sec.Data["DB"]) != "prod-secret" {
		t.Fatalf("prod DB = %q, want prod-secret", sec.Data["DB"])
	}

	// missing project_id (v3 with no input + no bundle field) → hard error, never
	// a 0-project decrypt.
	if _, err := BuildSecretForBundle(b, "auth", MaterializeInput{
		Env: "staging", Namespace: "demoapp", Cluster: "staging", Identity: []byte(s.Identity), ProjectID: 0,
	}); err == nil {
		t.Fatal("v3 build with no project_id must fail closed")
	}
}
