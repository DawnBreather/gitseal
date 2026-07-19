package client

import (
	"fmt"
	"strings"
)

// RepoYAMLPath is the policy file whose edit requires Owner (PolicyEditMinLevel).
const RepoYAMLPath = ".seald/repo.yaml"

// sealedPrefix is the directory holding committed SealedBundles.
const sealedPrefix = ".sealed/"

// ShowFunc returns the content of `path` at git revision `rev`. `ok` is false
// (with nil content, nil err) when the path does not exist at that rev (added or
// deleted file). A real implementation wraps `git show <rev>:<path>`; tests inject
// a fake. An actual error (bad rev, git failure) is returned as err.
type ShowFunc func(rev, path string) (content []byte, ok bool, err error)

// AuthzScan turns the MR's changed-file list into (sealed entry changes,
// repoYAMLTouched) by loading each touched .sealed/*.app.json at base and head and
// diffing them (DiffBundleEntries). It is git-plumbing-agnostic: the caller injects
// `show` (git show <rev>:<path>), so this is unit-testable without a real repo.
//
//   - Only paths under .sealed/ are diffed; a change to .seald/repo.yaml sets
//     repoYAMLTouched (governed by the Owner policy-edit rule); all other paths are
//     ignored here (they are gated by CODEOWNERS / other CI, not the sealed-write gate).
//   - A bundle absent at base (added) diffs against nil → all entries added; absent
//     at head (deleted) diffs nil-current → all removed.
//   - A .sealed file that fails to parse as a v2 bundle at head is a hard error
//     (fail closed) — plain `verify` will also catch it, but the gate must not
//     silently pass an unparseable sealed change.
func AuthzScan(changedFiles []string, baseRev, headRev string, show ShowFunc) (changes []EntryChange, repoYAMLTouched bool, err error) {
	for _, f := range changedFiles {
		f = strings.TrimPrefix(f, "./")
		if f == RepoYAMLPath {
			repoYAMLTouched = true
			continue
		}
		if !strings.HasPrefix(f, sealedPrefix) || !strings.HasSuffix(f, ".app.json") {
			continue
		}

		prior, perr := loadBundleAtRev(show, baseRev, f)
		if perr != nil {
			return nil, false, fmt.Errorf("%s@%s: %w", f, baseRev, perr)
		}
		cur, cerr := loadBundleAtRev(show, headRev, f)
		if cerr != nil {
			return nil, false, fmt.Errorf("%s@%s: %w", f, headRev, cerr)
		}
		if prior == nil && cur == nil {
			// Present in the changed-file list but absent at both revs — shouldn't
			// happen; treat as nothing rather than erroring.
			continue
		}
		for _, c := range DiffBundleEntries(prior, cur) {
			c.File = f // stamp the source file (for per-file signature attribution)
			changes = append(changes, c)
		}
	}
	return changes, repoYAMLTouched, nil
}

// loadBundleAtRev returns the parsed bundle at rev, or nil if the file is absent
// there (added/deleted). A present-but-unparseable bundle is an error (fail
// closed). A bundle whose version is NOT a per-env shape (v2/v3) is also a hard
// error: the write-authz diff only understands per-env sections, so a v1 /
// empty-version / unknown bundle would parse with Envs==nil, DiffBundleEntries
// would iterate nothing, and a real prod change relabelled under a non-per-env
// shape would show as ZERO changes — a silent bypass. Rejecting it here delivers
// the fail-closed guarantee this gate promises (all bundles in a v2/v3 repo carry
// env sections; plain `verify --strict` flags an un-migrated v1, not the authz path).
func loadBundleAtRev(show ShowFunc, rev, path string) (*SealedBundle, error) {
	data, ok, err := show(rev, path)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil // absent at this rev
	}
	b, err := ParseBundle(data)
	if err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}
	if !IsPerEnvVersion(b.Version) {
		return nil, fmt.Errorf("%s is version %q; the write-authz gate requires a per-env bundle (v2/v3/v4) — a flat/unknown bundle cannot be authorized (fail closed)", path, b.Version)
	}
	return b, nil
}
