package client

import (
	"encoding/json"
	"fmt"
	"os"
)

// StripKeyFromBundle removes `key` from EVERY env section of the v2 SealedBundle
// at `path` and rewrites the file, returning how many sections it was removed
// from. This is the mechanism behind `reseal --rotate KEY`: because the authoring
// path cannot detect a changed value (sealing is non-deterministic + offline), a
// present key is carried verbatim on reseal — so to actually rotate a value you
// must first make the key ABSENT (then a reseal re-seals it fresh). This makes
// that L10 ritual a first-class op instead of a manual JSON hand-edit.
//
// Removing an absent key is a no-op (returns 0, nil). A v1/non-v2 bundle is an
// error (rotation is a v2-per-env operation).
func StripKeyFromBundle(path, key string) (int, error) {
	b, err := LoadBundle(path)
	if err != nil {
		return 0, err
	}
	if !IsPerEnvVersion(b.Version) {
		return 0, fmt.Errorf("reseal --rotate needs a per-env bundle (v2/v3/v4); %s is version %q", path, b.Version)
	}
	removed := 0
	for env, sec := range b.Envs {
		if _, ok := sec.Entries[key]; ok {
			delete(sec.Entries, key)
			b.Envs[env] = sec
			removed++
		}
	}
	if removed == 0 {
		return 0, nil
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
		return 0, err
	}
	return removed, nil
}
