package client

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// ListSealedNames returns the secret names present in <repoRoot>/.sealed/
// (the basenames of *.json files), sorted, so `unseal --all` can iterate them.
func TestListSealedNames(t *testing.T) {
	dir := t.TempDir()
	sealed := filepath.Join(dir, ".sealed")
	os.MkdirAll(sealed, 0755)
	for _, n := range []string{"DATABASE_URL", "API_KEY", "REDIS_URL"} {
		os.WriteFile(filepath.Join(sealed, n+".json"), []byte("{}"), 0644)
	}
	// a non-json file must be ignored
	os.WriteFile(filepath.Join(sealed, "README.txt"), []byte("x"), 0644)

	got, err := ListSealedNames(dir)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	want := []string{"API_KEY", "DATABASE_URL", "REDIS_URL"}
	if len(got) != len(want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("want %v, got %v", want, got)
		}
	}
}

func TestListSealedNamesEmptyWhenNoDir(t *testing.T) {
	got, err := ListSealedNames(t.TempDir())
	if err != nil {
		t.Fatalf("missing .sealed dir should not error, got %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %v", got)
	}
}
