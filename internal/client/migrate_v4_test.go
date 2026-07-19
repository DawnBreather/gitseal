package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// MigrateBundleToV4 re-seals a v3 bundle to v4: decrypt each entry with
// the human private key, re-encrypt to the SAME [human, cluster] recipients but as
// a v4 envelope embedding the project PUBKEY, then re-sign each section with the
// v4 canonical bytes. Unlike v2→v3 (ciphertext-preserving), this DOES decrypt —
// but the PLAINTEXT is preserved (proven by decrypt-v4 == original), and per-env
// cluster isolation is kept (each env re-encrypts to its own cluster key).
func TestMigrateBundleToV4_ReSealsAndSigns(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey() // example cluster
	s, _ := crypto.GenerateRepoKey() // staging cluster
	clusters := map[string]string{"example": g.Recipient, "staging": s.Recipient}
	envCluster := map[string]string{"prod": "example", "staging": "staging"}

	// build a v3 bundle (SealBundleV2 writes v3) with two envs.
	path := filepath.Join(t.TempDir(), "auth.app.json")
	if _, err := SealBundleV2(path, human.Recipient, clusters, envCluster, 338, 40,
		map[string]map[string]string{
			"prod":    {"DB": "prod-db", "API": "prod-api"},
			"staging": {"DB": "stg-db"},
		}); err != nil {
		t.Fatal(err)
	}

	// signer (a dev key, for attribution)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	signer := NewSSHSignerFrom(mustSigner(t, priv))
	fp := KeyFingerprint(sshPub)

	res, err := MigrateBundleToV4(path, human.Identity, human.Recipient, clusters, envCluster, signer)
	if err != nil {
		t.Fatalf("MigrateBundleToV4: %v", err)
	}
	if res.Fingerprint != fp || len(res.EnvsSigned) != 2 {
		t.Fatalf("bad result: %+v", res)
	}

	b, _ := LoadBundle(path)
	if b.Version != BundleVersionV4 {
		t.Fatalf("version = %q, want v4", b.Version)
	}

	// (1) PLAINTEXT preserved: decrypt each v4 entry with the cluster key for its env.
	check := func(env, key, want, clusterID string) {
		ct := b.EnvCiphertext(env, key)
		pt, _, err := crypto.UnsealVerifiedByKey(ct, []byte(clusterID), human.Recipient)
		if err != nil {
			t.Fatalf("decrypt v4 %s/%s: %v", env, key, err)
		}
		if string(pt) != want {
			t.Fatalf("%s/%s = %q, want %q", env, key, pt, want)
		}
	}
	check("prod", "DB", "prod-db", g.Identity)
	check("prod", "API", "prod-api", g.Identity)
	check("staging", "DB", "stg-db", s.Identity)

	// (2) the human key can ALSO decrypt (broker unseal path) — sealed to [human, cluster].
	if pt, _, err := crypto.UnsealVerifiedByKey(b.EnvCiphertext("prod", "DB"), []byte(human.Identity), human.Recipient); err != nil || string(pt) != "prod-db" {
		t.Fatalf("human key must decrypt v4 prod/DB: %v %q", err, pt)
	}

	// (3) per-cluster isolation intact: staging key CANNOT decrypt the prod section.
	if _, _, err := crypto.UnsealVerifiedByKey(b.EnvCiphertext("prod", "DB"), []byte(s.Identity), human.Recipient); err == nil {
		t.Fatal("SECURITY: staging cluster key decrypted the v4 prod section")
	}

	// (4) signatures verify under the v4 gate (bound to the pubkey, not a numeric id).
	reg := stubResolver{users: map[string]ssh.PublicKey{fp: sshPub}, levels: map[string]int{fp: 50}}
	for _, env := range []string{"prod", "staging"} {
		if err := VerifySectionAuthzV4(human.Recipient, env, b.Envs[env], 40, reg); err != nil {
			t.Fatalf("v4 section %q must pass authz: %v", env, err)
		}
	}
}

// v4 canonical bytes bind to the pubkey: changing the pubkey (or any entry) changes
// the signed digest, so a v3 signature (bound to a numeric id) does NOT verify as v4.
func TestCanonicalSectionBytesV4_BindsPubkey(t *testing.T) {
	a, _ := crypto.GenerateRepoKey()
	b, _ := crypto.GenerateRepoKey()
	entries := map[string]string{"K": "ct"}
	if string(CanonicalSectionBytesV4(a.Recipient, "prod", entries)) == string(CanonicalSectionBytesV4(b.Recipient, "prod", entries)) {
		t.Fatal("different pubkeys must produce different canonical bytes")
	}
	// and different from the numeric v3 canonical (domain separation)
	if string(CanonicalSectionBytesV4(a.Recipient, "prod", entries)) == string(CanonicalSectionBytes(338, "prod", entries)) {
		t.Fatal("v4 canonical must be domain-separated from v3")
	}
}
