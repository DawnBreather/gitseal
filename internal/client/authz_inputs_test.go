package client

import "testing"

// --- authz CI input resolution (defect #1: trust only tamper-proof CI_* vars) --
//
// ResolveAuthzInputs derives the gate's trusted inputs from GitLab's PREDEFINED
// CI variables (which a merge request's own .gitlab-ci.yml cannot override) — not
// from CLI flags an attacker controls. It fails closed if a required predefined
// var is missing, or if a caller-supplied flag disagrees with the predefined
// value (that disagreement means someone is trying to spoof the diff/identity).

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestResolveAuthzInputs_FromCIVars(t *testing.T) {
	getenv := env(map[string]string{
		"CI_SERVER_HOST":                 "gitlab.example.com",
		"GITLAB_USER_ID":                 "42",
		"CI_PROJECT_ID":                  "338",
		"CI_MERGE_REQUEST_DIFF_BASE_SHA": "basesha",
		"CI_COMMIT_SHA":                  "headsha",
		"SEALD_AUTHZ_TOKEN":              "tok",
	})
	in, err := ResolveAuthzInputs(getenv, nil) // no flag overrides
	if err != nil {
		t.Fatalf("ResolveAuthzInputs: %v", err)
	}
	if in.Host != "gitlab.example.com" || in.UserID != 42 || in.ProjectID != 338 ||
		in.Base != "basesha" || in.Head != "headsha" || in.Token != "tok" {
		t.Fatalf("resolved inputs wrong: %+v", in)
	}
}

func TestResolveAuthzInputs_MissingRequiredFailsClosed(t *testing.T) {
	base := map[string]string{
		"CI_SERVER_HOST":                 "gitlab.example.com",
		"GITLAB_USER_ID":                 "42",
		"CI_PROJECT_ID":                  "338",
		"CI_MERGE_REQUEST_DIFF_BASE_SHA": "basesha",
		"CI_COMMIT_SHA":                  "headsha",
		"SEALD_AUTHZ_TOKEN":              "tok",
	}
	for _, missing := range []string{"GITLAB_USER_ID", "CI_PROJECT_ID", "CI_MERGE_REQUEST_DIFF_BASE_SHA", "CI_COMMIT_SHA", "SEALD_AUTHZ_TOKEN"} {
		m := map[string]string{}
		for k, v := range base {
			if k != missing {
				m[k] = v
			}
		}
		if _, err := ResolveAuthzInputs(env(m), nil); err == nil {
			t.Errorf("missing %s must fail closed, got nil", missing)
		}
	}
}

// A flag that DISAGREES with the predefined CI value is rejected (spoof attempt);
// a flag that MATCHES (or is absent) is fine.
func TestResolveAuthzInputs_FlagMismatchRejected(t *testing.T) {
	getenv := env(map[string]string{
		"CI_SERVER_HOST":                 "gitlab.example.com",
		"GITLAB_USER_ID":                 "42",
		"CI_PROJECT_ID":                  "338",
		"CI_MERGE_REQUEST_DIFF_BASE_SHA": "basesha",
		"CI_COMMIT_SHA":                  "headsha",
		"SEALD_AUTHZ_TOKEN":              "tok",
	})
	// attacker passes --user-id 50 hoping to impersonate an Owner
	if _, err := ResolveAuthzInputs(getenv, map[string]string{"user-id": "50"}); err == nil {
		t.Fatal("a --user-id disagreeing with GITLAB_USER_ID must be rejected")
	}
	// attacker passes --base <old sha> to hide a change already in base
	if _, err := ResolveAuthzInputs(getenv, map[string]string{"base": "otherbase"}); err == nil {
		t.Fatal("a --base disagreeing with CI_MERGE_REQUEST_DIFF_BASE_SHA must be rejected")
	}
	// matching flags are accepted
	if _, err := ResolveAuthzInputs(getenv, map[string]string{"user-id": "42", "base": "basesha"}); err != nil {
		t.Fatalf("matching flags should be accepted: %v", err)
	}
}

// SEALD_HOST (attacker-writable) is IGNORED; host always comes from the
// predefined CI_SERVER_HOST so it can't be pointed at a fake member-lookup server.
func TestResolveAuthzInputs_IgnoresSealdHostUsesCIServerHost(t *testing.T) {
	getenv := env(map[string]string{
		"SEALD_HOST":                     "evil.attacker.example", // must be ignored
		"CI_SERVER_HOST":                 "gitlab.example.com",
		"GITLAB_USER_ID":                 "42",
		"CI_PROJECT_ID":                  "338",
		"CI_MERGE_REQUEST_DIFF_BASE_SHA": "basesha",
		"CI_COMMIT_SHA":                  "headsha",
		"SEALD_AUTHZ_TOKEN":              "tok",
	})
	in, err := ResolveAuthzInputs(getenv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if in.Host != "gitlab.example.com" {
		t.Fatalf("host must be CI_SERVER_HOST, not SEALD_HOST: got %q", in.Host)
	}
}
