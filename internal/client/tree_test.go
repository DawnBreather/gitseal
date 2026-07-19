package client

import (
	"strings"
	"testing"
)

func TestRenderTree(t *testing.T) {
	b := &SealedBundle{
		Kind: "SealedBundle", Version: BundleVersionV3,
		Envs: map[string]EnvSection{
			"prod":    {Entries: map[string]string{"DB_HOST": "x", "API_KEY": "y"}, Sig: &EnvSectionSig{By: "SHA256:abc"}},
			"staging": {Entries: map[string]string{"DB_HOST": "z"}}, // unsigned
		},
	}
	out := RenderTree("auth", b)
	// header + both envs + sorted keys + signer/unsigned
	for _, want := range []string{"auth", "prod", "API_KEY DB_HOST", "SHA256:abc", "staging", "(unsigned)"} {
		if !strings.Contains(out, want) {
			t.Errorf("tree missing %q:\n%s", want, out)
		}
	}
	// no ciphertext blobs leak
	if strings.Contains(out, "\"x\"") || strings.Contains(out, "entries") {
		t.Errorf("tree must not show ciphertext/JSON:\n%s", out)
	}
}
