package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- admin onboard planner (Stage 1) -------------------------------------------
//
// PlanOnboard is the pure core of `sealdctl admin onboard`: given a project id, a
// keystore dir, and the cluster/env registry, it mints a per-repo key, writes the
// <pid>.key.json into the keystore (append — never touches other repos' keys), and
// returns the repo.yaml the target repo should commit. It is IDEMPOTENT: if the
// key file already exists it no-ops (no re-mint → no dead-key), unless force.

func regInputs() OnboardInputs {
	return OnboardInputs{
		ProjectID: 338,
		Envs: map[string]RegistryEnv{
			"prod":    {Cluster: "example", Namespace: "demoapp", MinLevel: 40, Recipient: "age1prodK"},
			"preprod": {Cluster: "example", Namespace: "demoapp-preprod", MinLevel: 40, Recipient: "age1preprodK"},
			"staging": {Cluster: "staging", Namespace: "demoapp", MinLevel: 30, Recipient: "age1stgK"},
		},
	}
}

func TestPlanOnboard_MintsKeyAndRepoYAML(t *testing.T) {
	ksdir := t.TempDir()
	in := regInputs()
	res, err := PlanOnboard(in, ksdir, false)
	if err != nil {
		t.Fatalf("PlanOnboard: %v", err)
	}
	if res.Minted != true {
		t.Fatal("first onboard should mint")
	}
	// key file exists + verifies against the recipient echoed into repo.yaml
	kfPath := filepath.Join(ksdir, KeyFileName(338))
	data, err := os.ReadFile(kfPath)
	if err != nil {
		t.Fatalf("key file not written: %v", err)
	}
	kf, err := ParseKeyFile(data)
	if err != nil {
		t.Fatalf("written key file invalid: %v", err)
	}
	if err := kf.Verify(res.Recipient); err != nil {
		t.Fatalf("written key must verify against its repo.yaml recipient: %v", err)
	}
	// v4: repo.yaml is RECIPIENT-ONLY — project_id + clusters + env_cluster
	// + env_min_level all live in the broker registry (projects.json), not the repo.
	if !strings.Contains(res.RepoYAML, "recipient: "+res.Recipient) {
		t.Errorf("repo.yaml must carry the recipient:\n%s", res.RepoYAML)
	}
	for _, mustNotHave := range []string{"project_id:", "clusters:", "env_cluster:", "env_min_level:"} {
		if strings.Contains(res.RepoYAML, mustNotHave) {
			t.Errorf("v4 repo.yaml must NOT carry %q (registry-owned now):\n%s", mustNotHave, res.RepoYAML)
		}
	}
}

func TestPlanOnboard_IdempotentNoOp(t *testing.T) {
	ksdir := t.TempDir()
	in := regInputs()
	first, err := PlanOnboard(in, ksdir, false)
	if err != nil {
		t.Fatal(err)
	}
	firstData, _ := os.ReadFile(filepath.Join(ksdir, KeyFileName(338)))

	// second run without force → no-op, key file byte-identical (NOT re-minted →
	// no dead-key footgun where the committed recipient no longer matches).
	second, err := PlanOnboard(in, ksdir, false)
	if err != nil {
		t.Fatalf("second onboard: %v", err)
	}
	if second.Minted {
		t.Fatal("second onboard must NOT re-mint (idempotent)")
	}
	if second.Recipient != first.Recipient {
		t.Fatal("idempotent onboard must echo the SAME existing recipient")
	}
	secondData, _ := os.ReadFile(filepath.Join(ksdir, KeyFileName(338)))
	if string(firstData) != string(secondData) {
		t.Fatal("key file must be byte-identical after a no-op onboard")
	}
}

func TestPlanOnboard_ForceRotates(t *testing.T) {
	ksdir := t.TempDir()
	in := regInputs()
	first, _ := PlanOnboard(in, ksdir, false)
	firstData, _ := os.ReadFile(filepath.Join(ksdir, KeyFileName(338)))

	rot, err := PlanOnboard(in, ksdir, true) // force = rotate
	if err != nil {
		t.Fatalf("force onboard: %v", err)
	}
	if !rot.Minted {
		t.Fatal("force onboard must re-mint")
	}
	if rot.Recipient == first.Recipient {
		t.Fatal("rotate must produce a NEW recipient")
	}
	rotData, _ := os.ReadFile(filepath.Join(ksdir, KeyFileName(338)))
	if string(firstData) == string(rotData) {
		t.Fatal("rotate must rewrite the key file")
	}
}

// An env missing its recipient/namespace is a config error surfaced early.
func TestPlanOnboard_RejectsBadRegistry(t *testing.T) {
	ksdir := t.TempDir()
	in := regInputs()
	in.Envs = map[string]RegistryEnv{"prod": {Cluster: "example", MinLevel: 40}} // no recipient/namespace
	if _, err := PlanOnboard(in, ksdir, false); err == nil {
		t.Fatal("env without a recipient/namespace must fail closed")
	}
}
