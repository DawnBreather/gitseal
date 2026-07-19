package client

import (
	"strings"
	"testing"
)

// --- write-authz verdict --------------------------------------------------------
//
// AuthzVerdict combines: the set of changed (env,key) entries, whether the MR
// touched .seald/repo.yaml, the author's effective GitLab level, and the repo
// policy (per-env required level + the fixed PolicyEditMinLevel=Owner-to-edit-
// policy rule). It returns violations (each naming env + required vs actual). OK
// == no violations.

func policyRC(t *testing.T) *RepoConfig {
	t.Helper()
	dir := writeRepoYAML(t, `project_id: 338
recipient: age1human
clusters: {example: age1G, staging: age1S}
env_cluster: {prod: example, preprod: example, staging: staging}
env_min_level: {prod: 40, preprod: 40, staging: 30}
`)
	rc, err := LoadRepoConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	return rc
}

func TestAuthzVerdict_DeveloperTouchesProd_Blocked(t *testing.T) {
	rc := policyRC(t)
	changes := []EntryChange{{Env: "prod", Key: "DB", Kind: EntryChanged}}
	v := AuthzVerdict(changes, false, 30, rc) // author is Developer (30), prod needs 40
	if v.OK() {
		t.Fatal("Developer changing prod should be blocked")
	}
	if !strings.Contains(strings.Join(v.Violations, "\n"), "prod") {
		t.Fatalf("violation should name prod: %v", v.Violations)
	}
}

func TestAuthzVerdict_DeveloperTouchesStagingOnly_Allowed(t *testing.T) {
	rc := policyRC(t)
	changes := []EntryChange{{Env: "staging", Key: "DB", Kind: EntryChanged}}
	v := AuthzVerdict(changes, false, 30, rc) // staging needs 30, author has 30
	if !v.OK() {
		t.Fatalf("Developer changing only staging should be allowed: %v", v.Violations)
	}
}

func TestAuthzVerdict_MaintainerTouchesProd_Allowed(t *testing.T) {
	rc := policyRC(t)
	changes := []EntryChange{
		{Env: "prod", Key: "DB", Kind: EntryChanged},
		{Env: "staging", Key: "X", Kind: EntryAdded},
	}
	v := AuthzVerdict(changes, false, 40, rc) // Maintainer meets prod=40 and staging=30
	if !v.OK() {
		t.Fatalf("Maintainer changing prod+staging should be allowed: %v", v.Violations)
	}
}

// The highest required level among touched envs governs; a mixed change where the
// author clears staging but not prod is still blocked (on prod).
func TestAuthzVerdict_MixedChange_BlockedOnHighest(t *testing.T) {
	rc := policyRC(t)
	changes := []EntryChange{
		{Env: "staging", Key: "OK", Kind: EntryChanged}, // 30 — cleared
		{Env: "prod", Key: "NO", Kind: EntryChanged},    // 40 — not cleared
	}
	v := AuthzVerdict(changes, false, 30, rc)
	if v.OK() {
		t.Fatal("Developer must be blocked on the prod entry even though staging is fine")
	}
	joined := strings.Join(v.Violations, "\n")
	if !strings.Contains(joined, "prod") || strings.Contains(joined, "staging OK") {
		t.Fatalf("only prod should be flagged: %v", v.Violations)
	}
}

// Editing .seald/repo.yaml requires Owner (50) — the policy-edit self-referential
// rule — regardless of which envs changed. A Maintainer (40) is blocked.
func TestAuthzVerdict_PolicyEdit_RequiresOwner(t *testing.T) {
	rc := policyRC(t)
	// No sealed-entry changes at all, but repo.yaml was touched.
	v := AuthzVerdict(nil, true, 40, rc)
	if v.OK() {
		t.Fatal("Maintainer (40) editing repo.yaml must be blocked (needs Owner 50)")
	}
	if !strings.Contains(strings.Join(v.Violations, "\n"), "repo.yaml") {
		t.Fatalf("violation should mention repo.yaml: %v", v.Violations)
	}
	// Owner (50) is allowed.
	if v := AuthzVerdict(nil, true, 50, rc); !v.OK() {
		t.Fatalf("Owner editing repo.yaml should be allowed: %v", v.Violations)
	}
}

// A sub-Owner who lowers env_min_level.prod AND changes prod in the same MR is
// caught by the policy-edit rule (repo.yaml touched → needs Owner), so the policy
// cannot be weakened from below.
func TestAuthzVerdict_PolicyEditPlusProdChange_Blocked(t *testing.T) {
	rc := policyRC(t)
	changes := []EntryChange{{Env: "prod", Key: "DB", Kind: EntryChanged}}
	v := AuthzVerdict(changes, true, 40, rc)
	if v.OK() {
		t.Fatal("Maintainer editing repo.yaml + prod must be blocked")
	}
}

// Level 0 (non-member) touching staging (needs 30) is blocked — fail closed.
func TestAuthzVerdict_NonMember_Blocked(t *testing.T) {
	rc := policyRC(t)
	changes := []EntryChange{{Env: "staging", Key: "X", Kind: EntryAdded}}
	if v := AuthzVerdict(changes, false, 0, rc); v.OK() {
		t.Fatal("non-member (level 0) must be blocked even on staging")
	}
}

// No changes and no repo.yaml edit → trivially OK (e.g. an MR that only touches
// environments/*/versions.yaml, gated elsewhere).
func TestAuthzVerdict_NoSealedChange_OK(t *testing.T) {
	rc := policyRC(t)
	if v := AuthzVerdict(nil, false, 0, rc); !v.OK() {
		t.Fatalf("no sealed change should pass authz: %v", v.Violations)
	}
}
