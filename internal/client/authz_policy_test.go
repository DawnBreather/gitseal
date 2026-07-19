package client

import "testing"

// --- write-authz policy: per-env required level in repo.yaml -------------------
//
// A v2 repo.yaml may carry an `env_min_level` map (env → required GitLab access
// level) that the CI write-authz gate consults to decide whether an MR author is
// allowed to change a given env's sealed entries. It is PUBLIC (a policy, not a
// secret) and CODEOWNER/Owner-gated. Resolution order for MinLevelForEnv:
//   1. env_min_level[env]           (explicit per-env policy)
//   2. min_access_level             (repo-wide scalar default, if > 0)
//   3. DefaultDeveloperLevel (30)   (final fallback)

func TestMinLevelForEnv_PerEnvWins(t *testing.T) {
	dir := writeRepoYAML(t, `project_id: 338
recipient: age1human
clusters:
  example: age1G
  staging: age1S
env_cluster:
  prod: example
  preprod: example
  staging: staging
env_min_level:
  prod: 40
  preprod: 40
  staging: 30
`)
	rc, err := LoadRepoConfig(dir)
	if err != nil {
		t.Fatalf("LoadRepoConfig: %v", err)
	}
	for env, want := range map[string]int{"prod": 40, "preprod": 40, "staging": 30} {
		if got := rc.MinLevelForEnv(env); got != want {
			t.Errorf("MinLevelForEnv(%q) = %d, want %d", env, got, want)
		}
	}
}

func TestMinLevelForEnv_FallsBackToScalar(t *testing.T) {
	dir := writeRepoYAML(t, `project_id: 338
recipient: age1human
min_access_level: 40
clusters: {example: age1G}
env_cluster: {prod: example}
`)
	rc, err := LoadRepoConfig(dir)
	if err != nil {
		t.Fatalf("LoadRepoConfig: %v", err)
	}
	// no env_min_level → every env resolves to the scalar default.
	if got := rc.MinLevelForEnv("prod"); got != 40 {
		t.Errorf("MinLevelForEnv(prod) with no env_min_level = %d, want scalar 40", got)
	}
	// an env not named in env_min_level also uses the scalar.
	if got := rc.MinLevelForEnv("staging"); got != 40 {
		t.Errorf("MinLevelForEnv(staging) unnamed = %d, want scalar 40", got)
	}
}

func TestMinLevelForEnv_FallsBackToDeveloperDefault(t *testing.T) {
	dir := writeRepoYAML(t, "project_id: 338\nrecipient: age1human\n")
	rc, err := LoadRepoConfig(dir)
	if err != nil {
		t.Fatalf("LoadRepoConfig: %v", err)
	}
	if got := rc.MinLevelForEnv("prod"); got != 30 {
		t.Errorf("MinLevelForEnv(prod) bare v1 = %d, want default 30", got)
	}
}

// env_min_level present but the specific env absent → scalar (or 30), NOT a zero
// that would let anyone (level 0) write. This guards the fail-closed intent: an
// unlisted env must never resolve to 0.
func TestMinLevelForEnv_UnlistedEnvNeverZero(t *testing.T) {
	dir := writeRepoYAML(t, `project_id: 338
recipient: age1human
env_min_level:
  prod: 40
`)
	rc, err := LoadRepoConfig(dir)
	if err != nil {
		t.Fatalf("LoadRepoConfig: %v", err)
	}
	if got := rc.MinLevelForEnv("staging"); got != 30 {
		t.Errorf("MinLevelForEnv(staging) unlisted = %d, want default 30 (never 0)", got)
	}
}
