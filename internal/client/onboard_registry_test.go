package client

import "testing"

// RegistryEntryFor turns an onboard's inputs + minted recipient into the project's
// broker-registry entry (projects.json), so `admin onboard` emits BOTH the
// recipient-only repo.yaml AND the ready registry row in one command — no manual
// projects.json editing. It reuses the ProjectRegistry mutation (fail-closed on an
// env whose cluster has no recipient).
func TestRegistryEntryFor(t *testing.T) {
	in := OnboardInputs{
		ProjectID: 412,
		Envs: map[string]RegistryEnv{
			"prod":    {Cluster: "example", Namespace: "demoapp", MinLevel: 40, Recipient: "age1prodK"},
			"staging": {Cluster: "staging", Namespace: "demoapp", MinLevel: 30, Recipient: "age1stgK"},
		},
	}
	reg, err := RegistryEntryFor(in, "age1projPUB")
	if err != nil {
		t.Fatalf("RegistryEntryFor: %v", err)
	}
	e, ok := reg["age1projPUB"]
	if !ok {
		t.Fatal("entry keyed by the recipient pubkey missing")
	}
	if e.ProjectID != 412 {
		t.Fatalf("project_id = %d", e.ProjectID)
	}
	if e.Envs["prod"].Recipient != "age1prodK" || e.Envs["prod"].Namespace != "demoapp" || e.Envs["prod"].MinLevel != 40 {
		t.Fatalf("prod env wrong: %+v", e.Envs["prod"])
	}

	// an env missing a recipient → fail closed.
	bad := OnboardInputs{ProjectID: 412, Envs: map[string]RegistryEnv{
		"qa": {Cluster: "example", Namespace: "demoapp-qa", MinLevel: 40},
	}}
	if _, err := RegistryEntryFor(bad, "age1x"); err == nil {
		t.Fatal("env with no recipient must fail closed")
	}
}
