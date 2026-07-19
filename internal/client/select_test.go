package client

import "testing"

// --- Task 4.2: SelectCiphertext env-aware selector -----------------------------
//
// SelectCiphertext is the one selector change the human unseal path needs for v2:
// given (env, name) it returns the v2 per-env ciphertext when the bundle is v2,
// and falls back to the flat v1 Ciphertext(name) for a v1 bundle. The broker POST
// is unchanged — this only picks WHICH stored blob to send.

// TestSelectCiphertextV2 proves a v2 bundle selects envs[env].entries[name], and
// that a missing env or missing name returns nil (never a wrong-env blob).
func TestSelectCiphertextV2(t *testing.T) {
	b := &SealedBundle{
		Version: "v2",
		Envs: map[string]EnvSection{
			// base64("prodblob") / base64("stgblob")
			"prod":    {Cluster: "example", Entries: map[string]string{"DB_HOST": "cHJvZGJsb2I="}},
			"staging": {Cluster: "staging", Entries: map[string]string{"DB_HOST": "c3RnYmxvYg=="}},
		},
	}
	if got := b.SelectCiphertext("prod", "DB_HOST"); string(got) != "prodblob" {
		t.Fatalf("SelectCiphertext(prod): got %q want prodblob", got)
	}
	if got := b.SelectCiphertext("staging", "DB_HOST"); string(got) != "stgblob" {
		t.Fatalf("SelectCiphertext(staging): got %q want stgblob", got)
	}
	if got := b.SelectCiphertext("prod", "MISSING"); got != nil {
		t.Fatalf("SelectCiphertext(missing name): got %q want nil", got)
	}
	if got := b.SelectCiphertext("bogus", "DB_HOST"); got != nil {
		t.Fatalf("SelectCiphertext(missing env): got %q want nil", got)
	}
}

// TestSelectCiphertextV1Fallback proves a v1 (flat) bundle ignores env and falls
// back to the flat Ciphertext(name) accessor — the pre-v2 unseal path is intact.
func TestSelectCiphertextV1Fallback(t *testing.T) {
	b := &SealedBundle{
		Version: "v1",
		// base64("flatblob")
		Entries: map[string]string{"API_KEY": "ZmxhdGJsb2I="},
	}
	// env is irrelevant for a v1 bundle — any env resolves to the flat entry.
	if got := b.SelectCiphertext("prod", "API_KEY"); string(got) != "flatblob" {
		t.Fatalf("SelectCiphertext(v1): got %q want flatblob", got)
	}
	if got := b.SelectCiphertext("", "API_KEY"); string(got) != "flatblob" {
		t.Fatalf("SelectCiphertext(v1, no env): got %q want flatblob", got)
	}
	if got := b.SelectCiphertext("prod", "MISSING"); got != nil {
		t.Fatalf("SelectCiphertext(v1 missing): got %q want nil", got)
	}
}
