package client

import (
	"strings"
	"testing"
)

// --- authz hardening (adversarial-review fixes) --------------------------------

// DEFECT #2: a non-per-env bundle at head must FAIL CLOSED, not parse as a
// flat/empty bundle whose (nil Envs) diff reports zero changes — which would hide
// a prod change relabelled as v1 / empty-version / an unknown version. (v2 and v3
// are the accepted per-env shapes; see TestAuthzScan_AcceptsV3.)
func TestAuthzScan_RejectsNonPerEnvAtHead(t *testing.T) {
	v1 := `{"kind":"SealedBundle","version":"v1","project_id":338,"entries":{"DB":"ct"}}`
	empty := `{"kind":"SealedBundle","version":"","project_id":338,"entries":{"DB":"ct"}}`
	unknown := `{"kind":"SealedBundle","version":"v9","project_id":338,"entries":{"DB":"ct"}}`
	for name, head := range map[string]string{"v1": v1, "empty-version": empty, "v9-unknown": unknown} {
		ft := fakeTree{"BASE": {}, "HEAD": {".sealed/auth.app.json": head}}
		_, _, err := AuthzScan([]string{".sealed/auth.app.json"}, "BASE", "HEAD", ft.show)
		if err == nil {
			t.Errorf("%s: AuthzScan must fail closed on a non-per-env bundle, got nil error", name)
		}
	}
}

// v3 (the current normalized shape) IS accepted by the authz scan, and its per-env
// entries diff correctly.
func TestAuthzScan_AcceptsV3(t *testing.T) {
	base := `{"kind":"SealedBundle","version":"v3","envs":{"prod":{"entries":{"A":"ct-A"}}}}`
	head := `{"kind":"SealedBundle","version":"v3","envs":{"prod":{"entries":{"A":"ct-A2"}}}}`
	ft := fakeTree{"BASE": {".sealed/auth.app.json": base}, "HEAD": {".sealed/auth.app.json": head}}
	changes, _, err := AuthzScan([]string{".sealed/auth.app.json"}, "BASE", "HEAD", ft.show)
	if err != nil {
		t.Fatalf("v3 must be accepted: %v", err)
	}
	if len(changes) != 1 || changes[0].Env != "prod" || changes[0].Key != "A" || changes[0].Kind != EntryChanged {
		t.Fatalf("v3 diff wrong: %+v", changes)
	}
}

// A non-v2 bundle at BASE is also rejected (all bundles in this repo are v2; a
// non-v2 base would be a tampered/degenerate diff base).
func TestAuthzScan_RejectsNonV2AtBase(t *testing.T) {
	v1 := `{"kind":"SealedBundle","version":"v1","project_id":338,"entries":{"DB":"ct"}}`
	head := v2json(map[string]string{"A": "ct-A"})
	ft := fakeTree{"BASE": {".sealed/auth.app.json": v1}, "HEAD": {".sealed/auth.app.json": head}}
	if _, _, err := AuthzScan([]string{".sealed/auth.app.json"}, "BASE", "HEAD", ft.show); err == nil {
		t.Fatal("non-v2 base must fail closed")
	}
}

// DEFECT #4/#5: AuthzVerdict must reject a touched env that is NOT declared in
// repo.yaml env_cluster — a fabricated env name (incl. a case variant like
// "PROD") otherwise falls back to the Developer default (30) via MinLevelForEnv
// and a level-30 author sails through.
func TestAuthzVerdict_RejectsUndeclaredEnv(t *testing.T) {
	rc := policyRC(t) // declares prod/preprod/staging
	for _, env := range []string{"prod_evil", "PROD", "Prod", "ephemeral"} {
		changes := []EntryChange{{Env: env, Key: "DB", Kind: EntryAdded}}
		v := AuthzVerdict(changes, false, 30, rc)
		if v.OK() {
			t.Errorf("undeclared env %q must be rejected (fail closed), author level 30 passed", env)
		}
		if !strings.Contains(strings.Join(v.Violations, "\n"), "env_cluster") {
			t.Errorf("undeclared env %q violation should cite env_cluster: %v", env, v.Violations)
		}
	}
}

// Even an OWNER (50) cannot write an undeclared env — the rule is structural
// (the env must exist in the registry), not a level bar.
func TestAuthzVerdict_UndeclaredEnvBlocksEvenOwner(t *testing.T) {
	rc := policyRC(t)
	changes := []EntryChange{{Env: "prod_evil", Key: "DB", Kind: EntryAdded}}
	if v := AuthzVerdict(changes, false, 50, rc); v.OK() {
		t.Fatal("undeclared env must be rejected even for an Owner")
	}
}

// A declared env still passes for an authorized author (regression: the new
// Rule 0 must not break the happy path).
func TestAuthzVerdict_DeclaredEnvStillPasses(t *testing.T) {
	rc := policyRC(t)
	changes := []EntryChange{{Env: "staging", Key: "DB", Kind: EntryChanged}}
	if v := AuthzVerdict(changes, false, 30, rc); !v.OK() {
		t.Fatalf("declared staging change by Developer should pass: %v", v.Violations)
	}
}
