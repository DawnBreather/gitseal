package client

import "testing"

// SetEnvV2 + RemoveEnv over the model (the SetEnv/SetClusterRecipient
// API was replaced). The env-shape assertions live in registry_env_test.go; this
// covers the mutation guards (project_id mismatch, remove-absent).
func TestRegistryRemoveEnv(t *testing.T) {
	r := ProjectRegistry{}
	pub := "age1proj"
	env := RegistryEnv{Cluster: "example", Namespace: "demoapp-qa", MinLevel: 40, Recipient: "age1qaK"}
	if err := r.SetEnvV2(pub, 338, "qa", env); err != nil {
		t.Fatalf("SetEnvV2: %v", err)
	}
	if err := r.RemoveEnv(pub, "qa"); err != nil {
		t.Fatal(err)
	}
	if _, ok := r[pub].Envs["qa"]; ok {
		t.Fatal("env not removed")
	}
	// removing a non-existent env is an error (typo guard)
	if err := r.RemoveEnv(pub, "nope"); err == nil {
		t.Fatal("removing an absent env must error")
	}
}

// A project_id mismatch on an existing entry is refused (you're editing the wrong
// project's row).
func TestRegistrySetEnv_ProjectIDMismatch(t *testing.T) {
	r := ProjectRegistry{}
	ok := RegistryEnv{Cluster: "c", Namespace: "ns", MinLevel: 40, Recipient: "age1k"}
	if err := r.SetEnvV2("age1p", 338, "prod", ok); err != nil {
		t.Fatal(err)
	}
	if err := r.SetEnvV2("age1p", 999, "staging", ok); err == nil {
		t.Fatal("changing an entry's project_id must be refused")
	}
}
