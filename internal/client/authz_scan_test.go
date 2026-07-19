package client

import (
	"sort"
	"testing"
)

// --- write-authz scan (git-plumbing-agnostic) ----------------------------------
//
// AuthzScan takes the MR's changed file list + an injected "show file at rev"
// function and produces (changes, repoYAMLTouched). It is the seam between the
// pure diff/verdict logic and real `git` — tested here with a fake shower so no
// real repo is needed.

// fakeTree maps rev → path → content (missing entry = file absent at that rev).
type fakeTree map[string]map[string]string

func (ft fakeTree) show(rev, path string) ([]byte, bool, error) {
	if m, ok := ft[rev]; ok {
		if c, ok := m[path]; ok {
			return []byte(c), true, nil
		}
	}
	return nil, false, nil
}

func v2json(entries map[string]string) string {
	// minimal valid v2 bundle with a single prod section carrying `entries`.
	b := `{"kind":"SealedBundle","version":"v2","project_id":338,` +
		`"recipients":{"human":"age1h","example":"age1G"},"envs":{"prod":{"cluster":"example","entries":{`
	first := true
	// deterministic key order
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !first {
			b += ","
		}
		b += `"` + k + `":"` + entries[k] + `"`
		first = false
	}
	b += `}}}}`
	return b
}

func TestAuthzScan_BundleChangedEntry(t *testing.T) {
	base := v2json(map[string]string{"A": "ct-A", "B": "ct-B"})
	head := v2json(map[string]string{"A": "ct-A", "B": "ct-B2"}) // B changed
	ft := fakeTree{
		"BASE": {".sealed/auth.app.json": base},
		"HEAD": {".sealed/auth.app.json": head},
	}
	changes, repoYAML, err := AuthzScan(
		[]string{".sealed/auth.app.json"}, "BASE", "HEAD", ft.show)
	if err != nil {
		t.Fatal(err)
	}
	if repoYAML {
		t.Error("repo.yaml not touched, should be false")
	}
	if len(changes) != 1 || changes[0].Env != "prod" || changes[0].Key != "B" || changes[0].Kind != EntryChanged {
		t.Fatalf("changes = %+v, want prod/B changed", changes)
	}
}

func TestAuthzScan_RepoYAMLTouched(t *testing.T) {
	ft := fakeTree{"BASE": {}, "HEAD": {}}
	_, repoYAML, err := AuthzScan(
		[]string{".seald/repo.yaml", "environments/prod/versions.yaml"}, "BASE", "HEAD", ft.show)
	if err != nil {
		t.Fatal(err)
	}
	if !repoYAML {
		t.Fatal("repo.yaml touched should be true")
	}
}

// A newly-added bundle (absent at base) → all its entries are additions.
func TestAuthzScan_NewBundle(t *testing.T) {
	head := v2json(map[string]string{"A": "ct-A"})
	ft := fakeTree{"BASE": {}, "HEAD": {".sealed/new.app.json": head}}
	changes, _, err := AuthzScan([]string{".sealed/new.app.json"}, "BASE", "HEAD", ft.show)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Kind != EntryAdded {
		t.Fatalf("new bundle changes = %+v, want one add", changes)
	}
}

// A deleted bundle (present at base, absent at head) → all its entries removed.
func TestAuthzScan_DeletedBundle(t *testing.T) {
	base := v2json(map[string]string{"A": "ct-A"})
	ft := fakeTree{"BASE": {".sealed/gone.app.json": base}, "HEAD": {}}
	changes, _, err := AuthzScan([]string{".sealed/gone.app.json"}, "BASE", "HEAD", ft.show)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Kind != EntryRemoved {
		t.Fatalf("deleted bundle changes = %+v, want one remove", changes)
	}
}

// Files outside .sealed/ and .seald/repo.yaml are ignored (e.g. chart edits).
func TestAuthzScan_IgnoresUnrelatedFiles(t *testing.T) {
	ft := fakeTree{"BASE": {}, "HEAD": {}}
	changes, repoYAML, err := AuthzScan(
		[]string{"charts/microservice/values.yaml", "README.md"}, "BASE", "HEAD", ft.show)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 || repoYAML {
		t.Fatalf("unrelated files should yield nothing: changes=%+v repoYAML=%v", changes, repoYAML)
	}
}
