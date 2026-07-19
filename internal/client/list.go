package client

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ListSealedNames returns the secret names in <repoRoot>/.sealed/ — the
// basenames of *.json files — so `unseal --all` can iterate them. A missing
// .sealed directory is not an error (returns empty).
func ListSealedNames(repoRoot string) ([]string, error) {
	dir := filepath.Join(repoRoot, ".sealed")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, ".json") {
			names = append(names, strings.TrimSuffix(n, ".json"))
		}
	}
	sort.Strings(names)
	return names, nil
}
