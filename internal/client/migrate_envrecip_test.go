package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// ReSealToEnvRecipients re-seals a v4 bundle from per-CLUSTER recipients
// to per-ENV recipients: decrypt each entry with the human key, re-encrypt to
// [project_pubkey, env.recipient]. prod and preprod (same cluster today) get
// DIFFERENT recipients → the prod section can no longer be decrypted by the
// preprod key. Plaintext is preserved; the section is re-signed.
func TestReSealToEnvRecipients(t *testing.T) {
	human, _ := crypto.GenerateRepoKey() // project key (broker unseal + decrypt)
	prodK, _ := crypto.GenerateRepoKey() // NEW per-env recipients
	preprodK, _ := crypto.GenerateRepoKey()
	oldCluster, _ := crypto.GenerateRepoKey() // the shared example key bundles are on now

	// build a v4 bundle sealed to [human, oldCluster] for prod+preprod (as today).
	path := filepath.Join(t.TempDir(), "auth.app.json")
	seal := func(pt string) string {
		ct, err := crypto.SealMultiV4([]byte(pt), []string{human.Recipient, oldCluster.Recipient}, human.Recipient, "DB", crypto.DefaultMinAccessLevel)
		if err != nil {
			t.Fatal(err)
		}
		return encB64FromBytes(ct)
	}
	b := &SealedBundle{Kind: "SealedBundle", Version: BundleVersionV4, Envs: map[string]EnvSection{
		"prod":    {Entries: map[string]string{"DB": seal("prod-secret")}},
		"preprod": {Entries: map[string]string{"DB": seal("preprod-secret")}},
	}}
	if err := writeBundle(path, b); err != nil {
		t.Fatal(err)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	signer := NewSSHSignerFrom(mustSigner(t, priv))

	envRecip := map[string]string{"prod": prodK.Recipient, "preprod": preprodK.Recipient}
	res, err := ReSealToEnvRecipients(path, human.Identity, human.Recipient, envRecip, signer)
	if err != nil {
		t.Fatalf("ReSealToEnvRecipients: %v", err)
	}
	if len(res.EnvsSigned) != 2 || res.Fingerprint != KeyFingerprint(sshPub) {
		t.Fatalf("bad result: %+v", res)
	}

	nb, _ := LoadBundle(path)
	// (1) prod decrypts with the PROD env key, preprod with the PREPROD env key
	if pt, _, err := crypto.UnsealVerifiedByKey(nb.EnvCiphertext("prod", "DB"), []byte(prodK.Identity), human.Recipient); err != nil || string(pt) != "prod-secret" {
		t.Fatalf("prod key must open prod: %v %q", err, pt)
	}
	if pt, _, err := crypto.UnsealVerifiedByKey(nb.EnvCiphertext("preprod", "DB"), []byte(preprodK.Identity), human.Recipient); err != nil || string(pt) != "preprod-secret" {
		t.Fatalf("preprod key must open preprod: %v %q", err, pt)
	}
	// (2) THE ISOLATION: prod env key CANNOT decrypt the preprod section (and vice-versa)
	if _, _, err := crypto.UnsealVerifiedByKey(nb.EnvCiphertext("preprod", "DB"), []byte(prodK.Identity), human.Recipient); err == nil {
		t.Fatal("SECURITY: prod env key decrypted the preprod section — isolation broken")
	}
	// (3) the old shared cluster key can no longer open EITHER (re-sealed away from it)
	if _, _, err := crypto.UnsealVerifiedByKey(nb.EnvCiphertext("prod", "DB"), []byte(oldCluster.Identity), human.Recipient); err == nil {
		t.Fatal("SECURITY: old shared cluster key still opens prod after re-seal")
	}
	// (4) the human/project key still opens everything (broker unseal path)
	if pt, _, err := crypto.UnsealVerifiedByKey(nb.EnvCiphertext("prod", "DB"), []byte(human.Identity), human.Recipient); err != nil || string(pt) != "prod-secret" {
		t.Fatalf("human key must still open prod: %v %q", err, pt)
	}
}

func encB64FromBytes(b []byte) string { return encB64(string(b)) }
