package client

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// A SealedBundle is one committed file holding many name→sealed-value entries
// plus the bundle's required access level. SealBundle replaces (re-seals all
// from the given plaintext map); LoadBundle reads it back.
func TestSealBundleReplaceAndLoad(t *testing.T) {
	kp, _ := crypto.GenerateRepoKey()
	dir := t.TempDir()
	path := filepath.Join(dir, "prod.json")

	secrets := map[string]string{"DATABASE_URL": "postgres://db", "API_KEY": "sk-1"}
	diff, err := SealBundle(path, kp.Recipient, 412, 40, secrets, false /*merge*/, false /*prune*/)
	if err != nil {
		t.Fatalf("SealBundle: %v", err)
	}
	sort.Strings(diff.Added)
	if len(diff.Added) != 2 || len(diff.Removed) != 0 {
		t.Fatalf("first seal diff: added=%v removed=%v", diff.Added, diff.Removed)
	}

	b, err := LoadBundle(path)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if b.Kind != "SealedBundle" || b.ProjectID != 412 || b.MinAccessLevel != 40 {
		t.Fatalf("bundle metadata wrong: %+v", b)
	}
	names := b.Names()
	sort.Strings(names)
	if len(names) != 2 || names[0] != "API_KEY" || names[1] != "DATABASE_URL" {
		t.Fatalf("bundle names: %v", names)
	}
	// each entry decrypts to its plaintext at level 40
	for name, want := range secrets {
		ct := b.Ciphertext(name)
		pt, level, err := crypto.UnsealVerified(ct, []byte(kp.Identity), 412)
		if err != nil || string(pt) != want || level != 40 {
			t.Fatalf("entry %s: %q/%d err=%v", name, pt, level, err)
		}
	}
}

// Replace removes keys no longer in the source.
func TestSealBundleReplaceRemoves(t *testing.T) {
	kp, _ := crypto.GenerateRepoKey()
	path := filepath.Join(t.TempDir(), "prod.json")
	_, _ = SealBundle(path, kp.Recipient, 412, 30, map[string]string{"A": "1", "B": "2"}, false, false)

	// replace with only {A,C}
	diff, err := SealBundle(path, kp.Recipient, 412, 30, map[string]string{"A": "9", "C": "3"}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(diff.Added)
	sort.Strings(diff.Removed)
	if len(diff.Added) != 1 || diff.Added[0] != "C" {
		t.Fatalf("added: %v", diff.Added)
	}
	if len(diff.Removed) != 1 || diff.Removed[0] != "B" {
		t.Fatalf("removed: %v", diff.Removed)
	}
	b, _ := LoadBundle(path)
	names := b.Names()
	sort.Strings(names)
	if len(names) != 2 || names[0] != "A" || names[1] != "C" {
		t.Fatalf("after replace, names: %v", names)
	}
}

// Merge keeps existing keys not in the source (no prune).
func TestSealBundleMergeKeeps(t *testing.T) {
	kp, _ := crypto.GenerateRepoKey()
	path := filepath.Join(t.TempDir(), "prod.json")
	_, _ = SealBundle(path, kp.Recipient, 412, 30, map[string]string{"A": "1", "B": "2"}, false, false)

	// merge in {C} → A,B kept, C added
	_, err := SealBundle(path, kp.Recipient, 412, 30, map[string]string{"C": "3"}, true /*merge*/, false)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := LoadBundle(path)
	names := b.Names()
	sort.Strings(names)
	if len(names) != 3 {
		t.Fatalf("merge should keep A,B and add C; got %v", names)
	}
	_ = os.Remove(path)
}
