package client

import (
	"fmt"
	"sort"
)

// MigrateResult reports what a v2→v3 migration did to one bundle file.
type MigrateResult struct {
	Fingerprint string   // the signer's SSH fingerprint (who signed the sections)
	EnvsSigned  []string // env names that were (re-)signed, sorted
	FromVersion string   // the bundle's version before migration ("v2" | "v3")
}

// MigrateBundleToV3 performs the v2→v3 transition on the bundle at path,
// in place, and returns what it did.
//
// It is a STRUCTURAL transform + signature — it NEVER decrypts:
//   - normalize: set version=v3 and DROP the denormalized fields (project_id,
//     min_access_level, recipients, the v1 flat recipient/entries) and each env
//     section's `cluster` label. Those are AEAD truth (project_id, level) or
//     registry-authoritative (recipients, env→cluster); keeping copies in the file
//     was the drift surface v3 removes.
//   - sign: sign each env section with the SSH signer over CanonicalSectionBytes
//     (project_id‖env‖sorted key/ciphertext), which hashes the EXISTING ciphertext.
//     The entries map is carried verbatim, so a migrated bundle decrypts to exactly
//     the same plaintext (materialize sees "unchanged").
//
// projectID must equal the bundle's own project_id (v2) — signing under a different
// id would bind the canonical bytes to the wrong project and the signature would be
// meaningless downstream, so a mismatch is a hard error (fail closed). A v1 flat
// bundle (no env sections) is refused: it predates the per-env model and must be
// resealed, not mechanically migrated. Re-running on an already-v3 bundle just
// re-signs it (idempotent shape).
func MigrateBundleToV3(path string, projectID int64, signer *SSHSigner) (*MigrateResult, error) {
	b, err := LoadBundle(path)
	if err != nil {
		return nil, err
	}
	switch b.Version {
	case BundleVersionV2, BundleVersionV3:
		// ok
	default:
		return nil, fmt.Errorf("migrate-v3: %s is version %q; only v2/v3 per-env bundles can be migrated (a v1 flat bundle must be resealed)", path, b.Version)
	}
	if len(b.Envs) == 0 {
		return nil, fmt.Errorf("migrate-v3: %s has no env sections to migrate", path)
	}
	// project_id guard: for v2 it must match the file's own id; v3 has no id in
	// file so we trust the caller (from repo.yaml). A v2 file with a different id
	// is refused — the caller is operating on the wrong project.
	if b.Version == BundleVersionV2 && b.ProjectID != 0 && b.ProjectID != projectID {
		return nil, fmt.Errorf("migrate-v3: %s project_id %d != caller project_id %d (refusing to sign under the wrong project)", path, b.ProjectID, projectID)
	}

	res := &MigrateResult{Fingerprint: signer.Fingerprint(), FromVersion: b.Version}

	// (1) NORMALIZE — drop denormalized fields + section cluster labels.
	b.Version = BundleVersionV3
	b.ProjectID = 0
	b.MinAccessLevel = 0
	b.Recipient = ""
	b.Recipients = nil
	b.Entries = nil

	// (2) SIGN each section over its existing ciphertext.
	for env, sec := range b.Envs {
		sec.Cluster = ""
		msg := CanonicalSectionBytes(projectID, env, sec.Entries)
		sig, err := signer.Sign(msg)
		if err != nil {
			return nil, fmt.Errorf("migrate-v3: sign env %q: %w", env, err)
		}
		sec.Sig = &EnvSectionSig{By: res.Fingerprint, Sig: sig}
		b.Envs[env] = sec
		res.EnvsSigned = append(res.EnvsSigned, env)
	}
	sort.Strings(res.EnvsSigned)

	if err := writeBundle(path, b); err != nil {
		return nil, err
	}
	return res, nil
}
