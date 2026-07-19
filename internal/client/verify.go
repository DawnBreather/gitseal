package client

import (
	"fmt"
	"sort"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// VerifyResult is the outcome of auditing one SealedBundle. Violations are hard
// failures that MUST red CI (exit non-zero); Warnings are advisories that MUST
// be surfaced but MUST NOT fail the pipeline on their own. Keeping the two in
// distinct fields makes it structurally impossible for the CLI to accidentally
// count an advisory toward its exit tally.
type VerifyResult struct {
	Violations []string // hard failures — exit non-zero
	Warnings   []string // advisories — print, do not fail
}

// OK reports whether the bundle passed the audit (no hard violations). Warnings
// do not affect OK.
func (r VerifyResult) OK() bool { return len(r.Violations) == 0 }

// VerifyBundle audits a SealedBundle against the repo's cluster registry
// (RepoConfig) and returns a VerifyResult separating hard Violations from
// advisory Warnings. A result with no Violations means the bundle passed. This
// is gitseal's decrypt-free CI tripwire (mandatory gate #1): it never needs a
// private key.
//
// For a v2 bundle it asserts:
//  1. every env declared in rc.EnvCluster is present in b.Envs (a missing env
//     means the bundle stopped covering an env the repo still ships).
//  2. every b.Envs[env].Cluster equals rc.EnvCluster[env] (the section's declared
//     cluster matches the repo registry).
//  3. every entry ciphertext in every env section has EXACTLY 2 recipient
//     stanzas ([human, that env's one cluster]). Any other count is a violation
//     naming svc/env/key — count==3 catches the FORBIDDEN cross-cluster
//     over-seal [human, G, S].
//  4. b.Recipients contains "human" (equal to rc.Recipient) and every cluster
//     that this bundle's env sections reference (with the recipient matching
//     rc.Clusters where the repo also declares it).
//
// For a v1 (flat) bundle the treatment depends on strict:
//   - non-strict (migration window): the bundle is reported as a single WARNING
//     ("v1 bundle not yet migrated to v2") and NO violation — verify passes
//     (exit 0) so CI can flag un-migrated bundles without reding the pipeline.
//     A v1 bundle carries no v2 structure to inspect, so nothing else is checked.
//   - strict (post-migration): v1 is a HARD violation and the bundle is
//     otherwise not inspected.
//
// L1 RESIDUAL — what verify CANNOT catch: age does not expose the recipient's
// long-term age1… pubkey on the wire (lessons.md L1), so from a ciphertext alone
// verify can only observe the stanza COUNT, never WHICH keys a stanza was sealed
// to. Consequently verify cannot detect an entry sealed to [human, WRONG-single-
// cluster] when the wrong cluster still yields stanza-count 2 AND the section's
// Cluster label was faked consistently to match it. That residual is covered by
// (a) the materialize-time cluster cross-check (gate #2, fail-closed, Phase 4) —
// the pod identity simply cannot decrypt an entry not sealed to its cluster —
// and (b) the fact that only an authorized keyholder can produce a validly-
// sealed entry in the first place. verify is the cheap early tripwire, not the
// isolation guarantee.
func VerifyBundle(b *SealedBundle, rc *RepoConfig, strict bool) VerifyResult {
	var res VerifyResult

	// v3 (normalized): no recipients registry, no cluster label — those
	// moved to the registry. Decrypt-free checks that still apply: every declared
	// env present + every entry has exactly 2 recipient stanzas [human, cluster].
	// The env→cluster/recipient MATCH is a registry-time check now, not here.
	if b.Version == BundleVersionV3 {
		for _, env := range sortedKeys(rc.EnvCluster) {
			if _, ok := b.Envs[env]; !ok {
				res.Violations = append(res.Violations, fmt.Sprintf("env %q declared in repo.yaml env_cluster is missing from the bundle", env))
			}
		}
		for _, env := range sortedKeys(b.Envs) {
			sec := b.Envs[env]
			if sec.Cluster != "" {
				res.Violations = append(res.Violations, fmt.Sprintf("env %q: v3 bundle must not carry a cluster label (normalized)", env))
			}
			for _, name := range sortedKeys(sec.Entries) {
				ct := b.EnvCiphertext(env, name)
				if ct == nil {
					res.Violations = append(res.Violations, fmt.Sprintf("%s/%s: unreadable (bad base64) entry", env, name))
					continue
				}
				n, err := crypto.RecipientStanzaCount(ct)
				if err != nil {
					res.Violations = append(res.Violations, fmt.Sprintf("%s/%s: not a valid age ciphertext: %v", env, name, err))
					continue
				}
				if n != 2 {
					res.Violations = append(res.Violations, fmt.Sprintf("%s/%s: %d recipient stanzas, want 2 [human, cluster]", env, name, n))
				}
			}
		}
		return res
	}

	// v1 (flat) or unversioned legacy bundle.
	if b.Version != BundleVersionV2 {
		if strict {
			res.Violations = append(res.Violations,
				fmt.Sprintf("v1 bundle not yet migrated to v2/v3 (strict): version=%q", b.Version))
		} else {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("v1 bundle not yet migrated to v2/v3: version=%q (advisory)", b.Version))
		}
		return res
	}

	// (4a) human recipient must be present and match the repo's human recipient.
	if h, ok := b.Recipients["human"]; !ok {
		res.Violations = append(res.Violations, "recipients registry is missing the \"human\" key")
	} else if rc.Recipient != "" && h != rc.Recipient {
		res.Violations = append(res.Violations, fmt.Sprintf("recipients[human] %q != repo.yaml recipient %q", h, rc.Recipient))
	}

	// (1) every env the repo registry declares must be present in the bundle.
	for _, env := range sortedKeys(rc.EnvCluster) {
		if _, ok := b.Envs[env]; !ok {
			res.Violations = append(res.Violations, fmt.Sprintf("env %q declared in repo.yaml env_cluster is missing from the bundle", env))
		}
	}

	// Walk the bundle's env sections in a deterministic order.
	for _, env := range sortedKeys(b.Envs) {
		sec := b.Envs[env]

		// (2) the section's declared cluster must match the repo registry.
		wantCluster, mapped := rc.EnvCluster[env]
		switch {
		case !mapped:
			res.Violations = append(res.Violations, fmt.Sprintf("env %q present in bundle but not mapped in repo.yaml env_cluster", env))
		case sec.Cluster != wantCluster:
			res.Violations = append(res.Violations, fmt.Sprintf("env %q section cluster %q != repo.yaml env_cluster %q", env, sec.Cluster, wantCluster))
		}

		// (4b) the cluster this section references must be present in the bundle's
		// recipients registry; where the repo also declares it, they must match.
		if sec.Cluster != "" {
			if r, ok := b.Recipients[sec.Cluster]; !ok {
				res.Violations = append(res.Violations, fmt.Sprintf("env %q references cluster %q absent from recipients registry", env, sec.Cluster))
			} else if want, ok := rc.Clusters[sec.Cluster]; ok && r != want {
				res.Violations = append(res.Violations, fmt.Sprintf("recipients[%s] %q != repo.yaml clusters[%s] %q", sec.Cluster, r, sec.Cluster, want))
			}
		}

		// (3) every entry must have EXACTLY 2 recipient stanzas.
		for _, name := range sortedKeys(sec.Entries) {
			ct := b.EnvCiphertext(env, name)
			if ct == nil {
				res.Violations = append(res.Violations, fmt.Sprintf("%s/%s: unreadable (bad base64) entry", env, name))
				continue
			}
			n, err := crypto.RecipientStanzaCount(ct)
			if err != nil {
				res.Violations = append(res.Violations, fmt.Sprintf("%s/%s: not a valid age ciphertext: %v", env, name, err))
				continue
			}
			if n != 2 {
				res.Violations = append(res.Violations, fmt.Sprintf("%s/%s: %d recipient stanzas, want 2 [human, cluster]", env, name, n))
			}
		}
	}

	return res
}

// sortedKeys returns the sorted keys of any string-keyed map (deterministic
// violation ordering + stable output).
func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
