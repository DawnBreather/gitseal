package client

import (
	"encoding/base64"
	"testing"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// v4: the materializer's anti-splice discriminator is the embedded
// PUBKEY == the repo's recipient (from MaterializeInput.Recipient), not a numeric
// project_id. A v4 section still decrypts with the mounted CLUSTER identity (the
// per-cluster isolation is unchanged — a section sealed to another cluster's key
// won't decrypt), and additionally the embedded owner-pubkey must equal this
// repo's recipient (catches a cross-repo splice: another repo's ciphertext sealed
// to the SAME cluster key would decrypt, but its embedded pubkey differs).
func TestMaterializeV4_ByRecipient(t *testing.T) {
	owner, _ := crypto.GenerateRepoKey() // this repo's identity (embedded pubkey)
	g, _ := crypto.GenerateRepoKey()     // example cluster key
	s, _ := crypto.GenerateRepoKey()     // staging cluster key

	// hand-build a v4 bundle: prod sealed to [owner, g], staging to [owner, s].
	seal := func(pt, clusterRcpt string) string {
		ct, err := crypto.SealMultiV4([]byte(pt), []string{owner.Recipient, clusterRcpt}, owner.Recipient, "DB", crypto.DefaultMinAccessLevel)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(ct)
	}
	b := &SealedBundle{
		Kind:    "SealedBundle",
		Version: BundleVersionV4,
		Envs: map[string]EnvSection{
			"prod":    {Entries: map[string]string{"DB": seal("prod-secret", g.Recipient)}},
			"staging": {Entries: map[string]string{"DB": seal("stg-secret", s.Recipient)}},
		},
	}

	// example identity + correct owner recipient → builds prod.
	sec, err := BuildSecretForBundle(b, "auth", MaterializeInput{
		Env: "prod", Namespace: "demoapp", Cluster: "example",
		Identity: []byte(g.Identity), Recipient: owner.Recipient,
	})
	if err != nil {
		t.Fatalf("example identity must build the v4 prod section: %v", err)
	}
	if string(sec.Data["DB"]) != "prod-secret" {
		t.Fatalf("prod DB = %q", sec.Data["DB"])
	}

	// staging identity building PROD → decrypt fails (per-cluster isolation intact).
	if _, err := BuildSecretForBundle(b, "auth", MaterializeInput{
		Env: "prod", Namespace: "demoapp", Cluster: "staging",
		Identity: []byte(s.Identity), Recipient: owner.Recipient,
	}); err == nil {
		t.Fatal("SECURITY: staging identity built the v4 prod section")
	}

	// ANTI-SPLICE: right cluster key, but WRONG expected recipient (a different
	// repo's pubkey) → embedded-pubkey mismatch aborts even though decrypt works.
	other, _ := crypto.GenerateRepoKey()
	if _, err := BuildSecretForBundle(b, "auth", MaterializeInput{
		Env: "prod", Namespace: "demoapp", Cluster: "example",
		Identity: []byte(g.Identity), Recipient: other.Recipient,
	}); err == nil {
		t.Fatal("SECURITY: v4 section with a mismatched owner recipient must abort (anti-splice)")
	}

	// v4 build with no Recipient supplied → fail closed (no discriminator to assert).
	if _, err := BuildSecretForBundle(b, "auth", MaterializeInput{
		Env: "prod", Namespace: "demoapp", Cluster: "example",
		Identity: []byte(g.Identity), Recipient: "",
	}); err == nil {
		t.Fatal("v4 build with no Recipient must fail closed")
	}
}
