package client

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// --- v3 normalized bundle --------------------------------------------
//
// v3 drops the denormalized fields (project_id, recipients, min_access_level,
// envs.<env>.cluster) — the file says only WHICH secrets exist per env (+ Stage-B
// sig). project_id/level are the AEAD truth; recipients/env→cluster live in the
// registry. v1/v2 still READ (migration window); seal WRITES v3.

func TestSealBundleV2WritesV3AndOmitsDenormalizedFields(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey()
	s, _ := crypto.GenerateRepoKey()
	path := filepath.Join(t.TempDir(), "geo.app.json")
	clusters := map[string]string{"example": g.Recipient, "staging": s.Recipient}
	envCluster := map[string]string{"prod": "example", "staging": "staging"}
	resolved := map[string]map[string]string{
		"prod":    {"A": "1"},
		"staging": {"A": "1"},
	}
	if _, err := SealBundleV2(path, human.Recipient, clusters, envCluster, 338, 30, resolved); err != nil {
		t.Fatalf("SealBundleV2: %v", err)
	}

	// on-disk JSON must be v3 and must NOT carry the denormalized fields
	raw := readFile(t, path)
	if !strings.Contains(raw, `"version": "v3"`) {
		t.Fatalf("expected version v3 on disk:\n%s", raw)
	}
	for _, forbidden := range []string{`"project_id"`, `"min_access_level"`, `"recipients"`, `"cluster"`, `"recipient"`} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("v3 bundle must not contain %s:\n%s", forbidden, raw)
		}
	}
	// but it MUST still carry envs + entries
	if !strings.Contains(raw, `"envs"`) || !strings.Contains(raw, `"entries"`) {
		t.Fatalf("v3 bundle missing envs/entries:\n%s", raw)
	}

	// round-trips + decrypts: prod entry opens with G, staging with S (crypto truth
	// intact even though the cluster label is gone).
	b, err := LoadBundle(path)
	if err != nil {
		t.Fatalf("LoadBundle v3: %v", err)
	}
	if b.Version != "v3" {
		t.Fatalf("parsed version = %q, want v3", b.Version)
	}
	prodCT := b.SelectCiphertext("prod", "A")
	if prodCT == nil {
		t.Fatal("prod/A ciphertext missing")
	}
	if _, _, err := crypto.UnsealVerified(prodCT, []byte(g.Identity), 338); err != nil {
		t.Fatalf("prod entry must open with example key: %v", err)
	}
	if _, _, err := crypto.UnsealVerified(prodCT, []byte(s.Identity), 338); err == nil {
		t.Fatal("SECURITY: staging key opened a prod entry")
	}
}

// v3 SelectCiphertext works (per-env), and a v3 bundle needs NO recipients registry
// to parse (unlike v2, which required it).
func TestParseV3NoRecipientsRequired(t *testing.T) {
	v3 := `{"kind":"SealedBundle","version":"v3","envs":{"prod":{"entries":{"A":"` +
		encB64("ct") + `"}}}}`
	b, err := ParseBundle([]byte(v3))
	if err != nil {
		t.Fatalf("v3 with no recipients must parse: %v", err)
	}
	if b.Version != "v3" || b.Envs["prod"].Entries["A"] == "" {
		t.Fatalf("bad v3 parse: %+v", b)
	}
}

// v2 bundles still parse (migration window): the old fields are tolerated.
func TestParseV2StillReads(t *testing.T) {
	v2 := `{"kind":"SealedBundle","version":"v2","project_id":338,"min_access_level":30,` +
		`"recipients":{"human":"age1h","example":"age1G"},` +
		`"envs":{"prod":{"cluster":"example","entries":{"A":"` + encB64("ct") + `"}}}}`
	b, err := ParseBundle([]byte(v2))
	if err != nil {
		t.Fatalf("v2 must still read: %v", err)
	}
	if b.Version != "v2" || b.Envs["prod"].Cluster != "example" {
		t.Fatalf("bad v2 parse: %+v", b)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func encB64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
