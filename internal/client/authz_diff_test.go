package client

import (
	"reflect"
	"sort"
	"testing"
)

// --- write-authz diff attribution ----------------------------------------------
//
// DiffBundleEntries compares a prior and current v2 SealedBundle and reports the
// set of (env, key) entries that were ADDED, REMOVED, or byte-CHANGED. A key
// carried verbatim (no-nonce-churn) has an identical base64 ciphertext on both
// sides → NOT reported. This is what lets the gate attribute a sealed change to
// an env without decrypting: a changed prod ciphertext == "someone (re)wrote
// prod's sealed data".

func mkV2(entriesByEnv map[string]map[string]string) *SealedBundle {
	envs := map[string]EnvSection{}
	for env, e := range entriesByEnv {
		cp := map[string]string{}
		for k, v := range e {
			cp[k] = v
		}
		envs[env] = EnvSection{Cluster: "c-" + env, Entries: cp}
	}
	return &SealedBundle{Kind: "SealedBundle", Version: "v2", ProjectID: 338, Envs: envs}
}

func sortedChanges(cs []EntryChange) []EntryChange {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Env != cs[j].Env {
			return cs[i].Env < cs[j].Env
		}
		return cs[i].Key < cs[j].Key
	})
	return cs
}

func TestDiffBundleEntries_DetectsChangeAddRemove(t *testing.T) {
	prior := mkV2(map[string]map[string]string{
		"prod":    {"A": "ct-A", "B": "ct-B"},
		"staging": {"A": "ct-A-s"},
	})
	cur := mkV2(map[string]map[string]string{
		"prod":    {"A": "ct-A", "B": "ct-B-NEW"}, // A verbatim, B changed
		"staging": {"A": "ct-A-s", "C": "ct-C-s"}, // A verbatim, C added
	})
	// prod/B changed, staging/C added; prod/A + staging/A verbatim → excluded.

	got := sortedChanges(DiffBundleEntries(prior, cur))
	want := []EntryChange{
		{Env: "prod", Key: "B", Kind: EntryChanged},
		{Env: "staging", Key: "C", Kind: EntryAdded},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("changes = %+v, want %+v", got, want)
	}
}

func TestDiffBundleEntries_RemovedKey(t *testing.T) {
	prior := mkV2(map[string]map[string]string{"prod": {"A": "ct-A", "B": "ct-B"}})
	cur := mkV2(map[string]map[string]string{"prod": {"A": "ct-A"}}) // B removed
	got := sortedChanges(DiffBundleEntries(prior, cur))
	want := []EntryChange{{Env: "prod", Key: "B", Kind: EntryRemoved}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("changes = %+v, want %+v", got, want)
	}
}

func TestDiffBundleEntries_NoChange(t *testing.T) {
	b := mkV2(map[string]map[string]string{"prod": {"A": "ct-A"}, "staging": {"X": "ct-X"}})
	// diff a bundle against an identical copy → no changes.
	if got := DiffBundleEntries(b, mkV2(map[string]map[string]string{"prod": {"A": "ct-A"}, "staging": {"X": "ct-X"}})); len(got) != 0 {
		t.Fatalf("identical bundles should have no changes, got %+v", got)
	}
}

// A brand-new env section (present in cur, absent in prior) → every entry ADDED.
func TestDiffBundleEntries_NewEnvSection(t *testing.T) {
	prior := mkV2(map[string]map[string]string{"prod": {"A": "ct-A"}})
	cur := mkV2(map[string]map[string]string{"prod": {"A": "ct-A"}, "preprod": {"A": "ct-A-p"}})
	got := sortedChanges(DiffBundleEntries(prior, cur))
	want := []EntryChange{{Env: "preprod", Key: "A", Kind: EntryAdded}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("changes = %+v, want %+v", got, want)
	}
}

// nil prior (bundle newly added in the MR) → every entry in cur is ADDED.
func TestDiffBundleEntries_NilPrior(t *testing.T) {
	cur := mkV2(map[string]map[string]string{"prod": {"A": "ct-A"}})
	got := sortedChanges(DiffBundleEntries(nil, cur))
	want := []EntryChange{{Env: "prod", Key: "A", Kind: EntryAdded}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("changes = %+v, want %+v", got, want)
	}
}

// EnvsTouched collapses a change set to the distinct envs affected — the unit the
// verdict actually gates on.
func TestEnvsTouched(t *testing.T) {
	cs := []EntryChange{
		{Env: "prod", Key: "B", Kind: EntryChanged},
		{Env: "prod", Key: "C", Kind: EntryAdded},
		{Env: "staging", Key: "A", Kind: EntryChanged},
	}
	got := EnvsTouched(cs)
	sort.Strings(got)
	want := []string{"prod", "staging"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EnvsTouched = %v, want %v", got, want)
	}
}
