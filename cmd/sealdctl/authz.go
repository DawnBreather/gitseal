package main

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/dawnbreather/gitseal/internal/client"
)

// cmdVerifyAuthz is the CI-only write-authorization gate: `verify --authz`.
//
// It decides whether the MR author is allowed to land the sealed-secret changes
// in their merge request — the WRITE-side mirror of the broker's read-side
// access-level check. Unlike plain `verify` (offline, decrypt-free, token-free),
// this needs network (GitLab member lookup) and a trustworthy identity, so it is
// a distinct, explicitly-opted-in mode that runs only in CI.
//
//	sealdctl verify --authz   # inputs come from predefined CI_* variables
//
// TRUST MODEL (adversarial-review hardening): every trusted input is read from
// GitLab's PREDEFINED CI variables via client.ResolveAuthzInputs, NOT from flags —
// because a merge request's own .gitlab-ci.yml (which GitLab executes) can set
// custom variables and job args but CANNOT override predefined ones. So:
//   - identity  = GITLAB_USER_ID (authenticated MR author; the git commit author
//     is spoofable and is NEVER used; a --user-id flag is only cross-checked);
//   - host      = CI_SERVER_HOST (the attacker-writable SEALD_HOST is IGNORED, so
//     the member lookup can't be redirected to a fake access_level:50 server);
//   - diff span = CI_MERGE_REQUEST_DIFF_BASE_SHA..CI_COMMIT_SHA (not --base/--head);
//   - token     = SEALD_AUTHZ_TOKEN (dedicated read_api PAT; MUST be a Protected
//     CI variable). Any supplied flag that DISAGREES with the CI value is a spoof
//     attempt → fail closed.
//
// Note this closes only the input-trust half of the ".gitlab-ci.yml is attacker-
// controlled" class; an attacker deleting/neutering the authz JOB itself is
// closed OUT of band (protect the CI config / CODEOWNERS on .gitlab-ci.yml /
// branch protection) — see the design doc.
//
// Flow: resolve trusted inputs → git-diff base..head → AuthzScan loads each
// touched .sealed/*.app.json at both revs (fail closed on any non-v2 bundle) and
// diffs them + flags .seald/repo.yaml edits → look up the author's effective
// level → AuthzVerdict (undeclared env / sub-threshold / policy-edit rules). Any
// violation → exit 1. FAIL CLOSED on any lookup, parse, or plumbing error.
func cmdVerifyAuthz(flags map[string]string) {
	in, err := client.ResolveAuthzInputs(os.Getenv, flags)
	if err != nil {
		fail("verify --authz: %v", err)
	}

	rc, err := resolveRC(".")
	if err != nil {
		fail("%v", err)
	}

	// 1. changed files across base..head.
	changedFiles, err := gitDiffNames(in.Base, in.Head)
	if err != nil {
		fail("git diff %s..%s: %v", in.Base, in.Head, err)
	}

	// 2. attribute sealed changes per (env,key) + detect a repo.yaml edit, loading
	//    each touched bundle at both revs via `git show`.
	changes, repoYAMLTouched, err := client.AuthzScan(changedFiles, in.Base, in.Head, gitShow)
	if err != nil {
		fail("authz scan: %v", err) // fail closed on any parse/plumbing error
	}

	if len(changes) == 0 && !repoYAMLTouched {
		fmt.Printf("authz OK: MR touches no sealed secrets or policy\n")
		return
	}

	// 3. author's effective level (fail closed on lookup error).
	level, err := client.ProjectMemberLevel(in.Host, in.Token, in.ProjectID, in.UserID)
	if err != nil {
		fail("member lookup (user %d on project %d): %v", in.UserID, in.ProjectID, err) // fail closed
	}

	// 4. author-level verdict: the MR author must meet each touched env's
	//    env_min_level; a repo.yaml edit needs Owner.
	res := client.AuthzVerdict(changes, repoYAMLTouched, level, rc)
	if !res.OK() {
		for _, v := range res.Violations {
			fmt.Fprintf(os.Stderr, "✗ authz: %s\n", v)
		}
		fail("write-authz DENIED: author (user %d, level %d) may not land these changes", in.UserID, level)
	}

	// 5. SIGNATURE enforcement: every CHANGED.sealed file's touched env
	//    sections at HEAD must carry a signature by a REGISTERED user whose LIVE
	//    level meets env_min_level. Stronger than the author check — it attributes
	//    each sealed section to a currently-authorized human (author ≠ signer is
	//    fine; both must be authorized). Resolver hits /v1/signer/resolve. Skipped
	//    only with --no-sig-check (migration window before users are onboarded).
	if flags["no-sig-check"] != "true" {
		resolver := &client.RemoteSignerResolver{BrokerURL: sigBrokerURL(), ProjectID: in.ProjectID}
		// which (file → set of changed envs) to verify.
		changedEnvsByFile := map[string]map[string]bool{}
		for _, c := range changes {
			if changedEnvsByFile[c.File] == nil {
				changedEnvsByFile[c.File] = map[string]bool{}
			}
			changedEnvsByFile[c.File][c.Env] = true
		}
		sigViol := 0
		for _, f := range sortedFileKeys(changedEnvsByFile) {
			data, ok, e := gitShow(in.Head, f)
			if e != nil || !ok {
				continue // file removed at head → no sections to attribute
			}
			b, e := client.ParseBundle(data)
			if e != nil {
				fmt.Fprintf(os.Stderr, "✗ authz(sig): %s: %v\n", f, e)
				sigViol++
				continue
			}
			for env := range changedEnvsByFile[f] {
				sec, has := b.Envs[env]
				if !has {
					continue
				}
				// v4 sections are signed over the pubkey-bound canonical
				// bytes, not the numeric id — dispatch to the matching verifier or a
				// v4 section's signature (correctly) won't verify.
				var verr error
				if b.Version == client.BundleVersionV4 {
					verr = client.VerifySectionAuthzV4(rc.Recipient, env, sec, rc.MinLevelForEnv(env), resolver)
				} else {
					verr = client.VerifySectionAuthz(in.ProjectID, env, sec, rc.MinLevelForEnv(env), resolver)
				}
				if verr != nil {
					fmt.Fprintf(os.Stderr, "✗ authz(sig) %s: %v\n", f, verr)
					sigViol++
				}
			}
		}
		if sigViol > 0 {
			fail("write-authz DENIED: %d env section(s) failed signature attribution (unsigned / unregistered signer / under-level / tampered)", sigViol)
		}
	}

	envs := client.EnvsTouched(changes)
	fmt.Printf("authz OK: author (user %d, level %d) + section signatures authorized for %d change(s) across envs %v%s\n",
		in.UserID, level, len(changes), envs, policyNote(repoYAMLTouched))
}

// sigBrokerURL is the broker base URL for signer resolution (SEALD_BROKER or default).
func sigBrokerURL() string {
	if v := os.Getenv("SEALD_BROKER"); v != "" {
		return v
	}
	return defaultBroker
}

// resolveRC loads .seald/repo.yaml and fills a v4 recipient-only config's
// operational fields (project_id / clusters / env_cluster / env_min_level) from the
// broker registry snapshot (cached, offline after first prime). A self-contained
// (v2/v3-era) repo.yaml is returned as-is with no network call. This is what the
// write/verify commands use so a collapsed repo.yaml still resolves everything.
func resolveRC(root string) (*client.RepoConfig, error) {
	return client.ResolveRepoConfig(root, sigBrokerURL(), client.DefaultSnapshotCachePath())
}

func sortedFileKeys(m map[string]map[string]bool) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func policyNote(repoYAMLTouched bool) string {
	if repoYAMLTouched {
		return " (+ .seald/repo.yaml policy edit)"
	}
	return ""
}

// gitDiffNames returns the paths changed between base and head (name-only, no
// rename detection surprises: -M is off so a rename shows as add+delete, which the
// gate treats conservatively).
func gitDiffNames(base, head string) ([]string, error) {
	out, err := exec.Command("git", "diff", "--name-only", base, head).Output()
	if err != nil {
		return nil, err
	}
	var files []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			files = append(files, l)
		}
	}
	return files, nil
}

// gitShow is the real ShowFunc: `git show <rev>:<path>`. A missing path at that
// rev (git exits non-zero with "exists on disk, but not in" / "does not exist")
// maps to ok=false so AuthzScan treats it as an add/delete rather than an error.
func gitShow(rev, path string) ([]byte, bool, error) {
	cmd := exec.Command("git", "show", rev+":"+path)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			// git prints "fatal: path '…' does not exist in '…'" / "exists on disk,
			// but not in '<rev>'" to stderr and exits 128 when the path is absent at
			// that rev — that's an expected add/delete, not a failure.
			msg := string(ee.Stderr)
			if strings.Contains(msg, "does not exist in") ||
				strings.Contains(msg, "exists on disk, but not in") ||
				strings.Contains(msg, "no such path") {
				return nil, false, nil
			}
			return nil, false, fmt.Errorf("git show %s:%s: %s", rev, path, strings.TrimSpace(msg))
		}
		return nil, false, err
	}
	return out, true, nil
}
