package client

import "sort"

// EntryChangeKind classifies how one (env, key) entry changed between a prior and
// current bundle.
type EntryChangeKind string

const (
	EntryAdded   EntryChangeKind = "added"
	EntryRemoved EntryChangeKind = "removed"
	EntryChanged EntryChangeKind = "changed" // ciphertext bytes differ
)

// EntryChange is one changed (env, key) entry in a bundle diff. File is the
// .sealed/*.app.json path it came from (stamped by AuthzScan; empty for a bare
// DiffBundleEntries call).
type EntryChange struct {
	File string
	Env  string
	Key  string
	Kind EntryChangeKind
}

// DiffBundleEntries compares the per-env entries of a prior and current v2
// SealedBundle and returns every (env, key) that was added, removed, or whose
// stored base64 ciphertext changed. A key present on both sides with identical
// ciphertext (the no-nonce-churn verbatim carry-over) is NOT reported — so a
// reseal that re-supplies an unchanged key set produces an empty diff, and any
// reported entry is a genuine (re)write of that env's sealed data.
//
// Comparison is on the STORED base64 string (not decoded bytes): the gate never
// decrypts, and identical stored strings mean identical ciphertext. A nil prior
// (the bundle was newly added in the MR) makes every current entry an addition.
// Only v2 sections are compared; a v1/flat bundle has no per-env entries and
// yields no per-env changes here (a v1 bundle in a v2 repo is a separate
// structural violation caught by plain verify).
func DiffBundleEntries(prior, cur *SealedBundle) []EntryChange {
	var out []EntryChange

	priorEnvs := map[string]EnvSection{}
	if prior != nil {
		priorEnvs = prior.Envs
	}
	curEnvs := map[string]EnvSection{}
	if cur != nil {
		curEnvs = cur.Envs
	}

	// added / changed: walk current entries, compare against prior.
	for env, sec := range curEnvs {
		priorSec, hadEnv := priorEnvs[env]
		for key, curCT := range sec.Entries {
			priorCT, hadKey := "", false
			if hadEnv {
				priorCT, hadKey = priorSec.Entries[key]
			}
			switch {
			case !hadKey:
				out = append(out, EntryChange{Env: env, Key: key, Kind: EntryAdded})
			case priorCT != curCT:
				out = append(out, EntryChange{Env: env, Key: key, Kind: EntryChanged})
			}
		}
	}

	// removed: prior entries absent from current.
	for env, priorSec := range priorEnvs {
		curSec, hasEnv := curEnvs[env]
		for key := range priorSec.Entries {
			_, stillThere := "", false
			if hasEnv {
				_, stillThere = curSec.Entries[key]
			}
			if !stillThere {
				out = append(out, EntryChange{Env: env, Key: key, Kind: EntryRemoved})
			}
		}
	}

	return out
}

// EnvsTouched returns the distinct env names appearing in a change set — the unit
// the write-authz verdict gates on (a change to ANY entry in env E requires the
// author to meet E's required level).
func EnvsTouched(changes []EntryChange) []string {
	seen := map[string]bool{}
	var envs []string
	for _, c := range changes {
		if !seen[c.Env] {
			seen[c.Env] = true
			envs = append(envs, c.Env)
		}
	}
	sort.Strings(envs)
	return envs
}
