package client

import (
	"fmt"
	"sort"
)

// PolicyEditMinLevel is the GitLab access level required to change .seald/repo.yaml
// AT ALL. repo.yaml defines the gate itself (per-env required levels, cluster
// recipients, env→cluster map), so editing it is the highest-trust act in the
// repo and sits above every per-env write level. Owner (50). This is enforced by
// the gate itself rather than by CODEOWNERS, because code-owner approval requires
// GitLab Premium (off on this instance) — so the self-referential Owner rule is
// what actually prevents an attacker from lowering env_min_level from below.
const PolicyEditMinLevel = 50

// AuthzResult is the outcome of the write-authz gate. OK == no violations.
type AuthzResult struct {
	Violations []string
}

// OK reports whether the author is authorized for every change in the MR.
func (r AuthzResult) OK() bool { return len(r.Violations) == 0 }

// AuthzVerdict decides whether an MR author is authorized to land the sealed
// changes in their MR. Inputs:
//
//   - changes:       the (env,key) entries added/removed/changed in .sealed/* (from DiffBundleEntries)
//   - repoYAMLTouched: whether the MR diff touches .seald/repo.yaml
//   - authorLevel:   the MR author's effective GitLab access level (0 if not a member — fail closed)
//   - rc:            the repo config (per-env policy via MinLevelForEnv)
//
// Rules (all must pass):
//  1. For every env touched by a sealed change, authorLevel >= rc.MinLevelForEnv(env).
//  2. If repo.yaml was touched, authorLevel >= PolicyEditMinLevel (Owner) — the
//     self-referential policy-edit rule, independent of which envs changed.
//
// Each failed rule yields one violation naming the env + required vs actual, in
// deterministic order for stable CI output.
func AuthzVerdict(changes []EntryChange, repoYAMLTouched bool, authorLevel int, rc *RepoConfig) AuthzResult {
	var res AuthzResult

	// Collapse to the distinct touched envs first so a violation is reported once
	// per env, not once per changed key.
	for _, env := range EnvsTouched(changes) {
		// Rule 0 (fail closed): the env MUST be declared in repo.yaml env_cluster.
		// Without this, a fabricated env name — a bogus "prod_alias", or a case
		// variant like "PROD" that misses the "prod" policy key — falls through
		// MinLevelForEnv to the Developer default (30) and a level-30 author writes
		// it freely (potentially sealed to a real cluster key). Mirrors the
		// structural check in VerifyBundle (verify.go). This is a STRUCTURAL bar,
		// not a level bar: an undeclared env is refused regardless of author level.
		if _, declared := rc.EnvCluster[env]; !declared {
			res.Violations = append(res.Violations,
				fmt.Sprintf("env %q: not declared in repo.yaml env_cluster — an undeclared env cannot be written (fail closed)", env))
			continue
		}

		// Rule 1: per-env write level.
		req := rc.MinLevelForEnv(env)
		if authorLevel < req {
			res.Violations = append(res.Violations,
				fmt.Sprintf("env %q: changing its sealed secrets needs access level %d, author has %d", env, req, authorLevel))
		}
	}

	// Rule 2: editing the policy file itself requires Owner.
	if repoYAMLTouched && authorLevel < PolicyEditMinLevel {
		res.Violations = append(res.Violations,
			fmt.Sprintf(".seald/repo.yaml: editing the write-authz policy needs access level %d (Owner), author has %d", PolicyEditMinLevel, authorLevel))
	}

	sort.Strings(res.Violations)
	return res
}
