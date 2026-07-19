package broker

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// LoadRegistry reads the broker registry from a directory (mounted out-of-band
// Secret, never git — like the keystore). Layout:
//
//	<dir>/projects.json   {"<project pubkey>": {project_id, env_cluster, env_min_level, cluster_recipients}}
//	<dir>/users.json      {"SHA256:<fp>": <gitlab user_id>}       (optional until user onboarding is live)
//	<dir>/userkeys.json   {"SHA256:<fp>": "<authorized-key line>"} (optional; verifies challenge sigs)
//
// Missing users.json / userkeys.json is tolerated (empty maps) so the registry
// can be seeded projects-first. A missing/unparseable projects.json is fatal
// (fail closed — a broker with no project registry can't resolve snapshots or
// signers). NOTE: users.json and userkeys.json are a PAIR — authViaSSH needs BOTH
// (fp→uid to identify the caller, fp→key to verify the challenge signature), so a
// broker seeded with users.json but no userkeys.json denies every SSH unseal at
// "no registered public key". Onboard both rows together (`admin onboard-user`
// prints both).
func LoadRegistry(dir string) (*Registry, error) {
	reg := &Registry{
		Projects: map[string]ProjectEntry{},
		Users:    map[string]int64{},
		UserKeys: map[string]string{},
	}

	pj, err := os.ReadFile(filepath.Join(dir, "projects.json"))
	if err != nil {
		return nil, fmt.Errorf("read registry projects.json: %w", err)
	}
	if err := json.Unmarshal(pj, &reg.Projects); err != nil {
		return nil, fmt.Errorf("parse projects.json: %w", err)
	}

	if err := loadOptionalJSON(filepath.Join(dir, "users.json"), &reg.Users); err != nil {
		return nil, err
	}
	if err := loadOptionalJSON(filepath.Join(dir, "userkeys.json"), &reg.UserKeys); err != nil {
		return nil, err
	}
	return reg, nil
}

// loadOptionalJSON unmarshals a registry file into dst if present; a missing file
// is not an error (leaves dst untouched), but a present-and-unparseable file is.
func loadOptionalJSON(path string, dst any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read registry %s: %w", filepath.Base(path), err)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}
	return nil
}
