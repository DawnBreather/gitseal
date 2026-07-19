package client

import (
	"fmt"
	"strconv"
)

// AuthzInputs are the trusted inputs the write-authz gate runs on, all derived
// from GitLab's PREDEFINED CI variables rather than caller-supplied flags.
type AuthzInputs struct {
	Host      string // GitLab host for the member lookup (CI_SERVER_HOST)
	ProjectID int64  // CI_PROJECT_ID
	UserID    int64  // GITLAB_USER_ID — the authenticated MR author
	Base      string // CI_MERGE_REQUEST_DIFF_BASE_SHA — the merge-base
	Head      string // CI_COMMIT_SHA
	Token     string // SEALD_AUTHZ_TOKEN — dedicated read_api PAT (must be a Protected CI var)
}

// ResolveAuthzInputs derives the gate's trusted inputs from PREDEFINED GitLab CI
// variables (via getenv) and FAILS CLOSED on anything missing. It is the fix for
// the "attacker edits .gitlab-ci.yml" bypass class: a merge request's own
// .gitlab-ci.yml can freely set custom `variables:` and job flags, but it CANNOT
// override GitLab's predefined variables (CI_SERVER_HOST, GITLAB_USER_ID,
// CI_PROJECT_ID, CI_MERGE_REQUEST_DIFF_BASE_SHA, CI_COMMIT_SHA — injected by the
// runner). So the gate trusts ONLY those, never a flag.
//
//   - Host comes from CI_SERVER_HOST — the attacker-writable SEALD_HOST is IGNORED
//     here, so the member lookup can't be redirected to a fake server returning
//     access_level:50.
//   - UserID is GITLAB_USER_ID (the authenticated author), never a --user-id flag.
//   - Base/Head are the CI merge-base/commit, never --base/--head flags.
//   - Token is SEALD_AUTHZ_TOKEN, which MUST be marked a *Protected* CI variable
//     (not merely masked) so it is not exposed to pipelines on unprotected
//     attacker branches.
//
// `flags` (the parsed CLI flags) are accepted ONLY as an equality cross-check: if
// a flag is present it MUST equal the corresponding predefined value, else the
// call fails (a mismatch is a spoof attempt). This lets the documented CLI form
// (`--base $CI_MERGE_REQUEST_DIFF_BASE_SHA ...`) keep working while making a
// divergent flag a hard error rather than a trusted override.
func ResolveAuthzInputs(getenv func(string) string, flags map[string]string) (AuthzInputs, error) {
	var in AuthzInputs

	in.Host = getenv("CI_SERVER_HOST")
	if in.Host == "" {
		return in, fmt.Errorf("CI_SERVER_HOST not set — verify --authz must run in a GitLab CI pipeline (it trusts predefined CI_* variables, not flags)")
	}

	pid, err := requireIntEnv(getenv, "CI_PROJECT_ID")
	if err != nil {
		return in, err
	}
	in.ProjectID = pid

	uid, err := requireIntEnv(getenv, "GITLAB_USER_ID")
	if err != nil {
		return in, err
	}
	in.UserID = uid

	in.Base = getenv("CI_MERGE_REQUEST_DIFF_BASE_SHA")
	if in.Base == "" {
		return in, fmt.Errorf("CI_MERGE_REQUEST_DIFF_BASE_SHA not set — verify --authz runs only on merge_request_event pipelines")
	}
	in.Head = getenv("CI_COMMIT_SHA")
	if in.Head == "" {
		return in, fmt.Errorf("CI_COMMIT_SHA not set")
	}

	in.Token = getenv("SEALD_AUTHZ_TOKEN")
	if in.Token == "" {
		return in, fmt.Errorf("SEALD_AUTHZ_TOKEN not set (dedicated read_api PAT for member lookup; mark it a Protected CI variable)")
	}

	// Cross-check any supplied flags against the predefined values; a disagreement
	// is a spoof attempt → fail closed.
	if err := crosscheck(flags, "project-id", in.ProjectID); err != nil {
		return in, err
	}
	if err := crosscheck(flags, "user-id", in.UserID); err != nil {
		return in, err
	}
	if err := crosscheckStr(flags, "base", in.Base); err != nil {
		return in, err
	}
	// --head may legitimately be the literal "HEAD" (its default); only a concrete
	// SHA that disagrees with CI_COMMIT_SHA is a spoof.
	if v, ok := flags["head"]; ok && v != "" && v != "HEAD" && v != in.Head {
		return in, fmt.Errorf("--head %q disagrees with CI_COMMIT_SHA %q (spoof attempt — fail closed)", v, in.Head)
	}

	return in, nil
}

func requireIntEnv(getenv func(string) string, key string) (int64, error) {
	v := getenv(key)
	if v == "" {
		return 0, fmt.Errorf("%s not set", key)
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not an integer", key, v)
	}
	return n, nil
}

func crosscheck(flags map[string]string, name string, want int64) error {
	v, ok := flags[name]
	if !ok || v == "" {
		return nil
	}
	got, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fmt.Errorf("--%s %q is not an integer", name, v)
	}
	if got != want {
		return fmt.Errorf("--%s %d disagrees with the CI value %d (spoof attempt — fail closed)", name, got, want)
	}
	return nil
}

func crosscheckStr(flags map[string]string, name, want string) error {
	v, ok := flags[name]
	if !ok || v == "" {
		return nil
	}
	if v != want {
		return fmt.Errorf("--%s %q disagrees with the CI value %q (spoof attempt — fail closed)", name, v, want)
	}
	return nil
}
