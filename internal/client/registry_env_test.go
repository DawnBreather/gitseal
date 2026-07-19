package client

import (
	"strings"
	"testing"
)

// an environment is a first-class {cluster, namespace, min_level,
// recipient} in the registry — env owns its crypto recipient (prod≠preprod even on
// one cluster) + its delivery namespace. This replaces the parallel
// cluster_recipients/env_cluster/env_min_level maps.
func TestRegistryEnv_SetAndResolve(t *testing.T) {
	r := ProjectRegistry{}
	pub := "age1proj"

	if err := r.SetEnvV2(pub, 338, "prod", RegistryEnv{
		Cluster: "example", Namespace: "demoapp", MinLevel: 40, Recipient: "age1prodKEY",
	}); err != nil {
		t.Fatalf("SetEnvV2: %v", err)
	}
	if err := r.SetEnvV2(pub, 338, "preprod", RegistryEnv{
		Cluster: "example", Namespace: "demoapp-preprod", MinLevel: 40, Recipient: "age1preprodKEY",
	}); err != nil {
		t.Fatal(err)
	}

	e := r[pub]
	if e.Envs["prod"].Recipient != "age1prodKEY" || e.Envs["prod"].Namespace != "demoapp" {
		t.Fatalf("prod env wrong: %+v", e.Envs["prod"])
	}
	// prod and preprod share a cluster but have DIFFERENT recipients (the whole point)
	if e.Envs["prod"].Recipient == e.Envs["preprod"].Recipient {
		t.Fatal("prod and preprod must have distinct recipients (per-env crypto boundary)")
	}
	if e.Envs["prod"].Cluster != e.Envs["preprod"].Cluster {
		t.Fatal("prod and preprod share the example cluster (informational)")
	}

	// resolve helpers used by seal/materialize
	rec, ok := e.EnvRecipient("prod")
	if !ok || rec != "age1prodKEY" {
		t.Fatalf("EnvRecipient(prod) = %q %v", rec, ok)
	}
	ns, ok := e.EnvNamespace("preprod")
	if !ok || ns != "demoapp-preprod" {
		t.Fatalf("EnvNamespace(preprod) = %q %v", ns, ok)
	}

	// a missing recipient is rejected (nothing to seal to)
	if err := r.SetEnvV2(pub, 338, "qa", RegistryEnv{Cluster: "example", Namespace: "demoapp-qa", MinLevel: 40}); err == nil {
		t.Fatal("SetEnvV2 without a recipient must fail closed")
	}
}

// Back-compat: an OLD-shape projects.json (cluster_recipients + env_cluster +
// env_min_level) parses into the new Envs model, so a mid-migration registry still
// resolves. (prod/preprod inherit the shared cluster recipient until re-sealed.)
func TestRegistryEnv_BackCompatOldShape(t *testing.T) {
	old := `{"age1p":{"project_id":338,
	  "env_cluster":{"prod":"example","preprod":"example","staging":"staging"},
	  "env_min_level":{"prod":40,"preprod":40,"staging":30},
	  "cluster_recipients":{"example":"age1G","staging":"age1S"}}}`
	r, err := ParseProjectRegistry([]byte(old))
	if err != nil {
		t.Fatalf("parse old shape: %v", err)
	}
	e := r["age1p"]
	// old shape → Envs derived: recipient = the cluster recipient (shared), namespace absent
	if rec, ok := e.EnvRecipient("prod"); !ok || rec != "age1G" {
		t.Fatalf("back-compat prod recipient = %q %v (want age1G)", rec, ok)
	}
	if rec, _ := e.EnvRecipient("staging"); rec != "age1S" {
		t.Fatalf("back-compat staging recipient wrong")
	}
	if e.Envs["prod"].MinLevel != 40 || e.Envs["staging"].MinLevel != 30 {
		t.Fatalf("back-compat min levels lost")
	}
}

// The new shape round-trips through JSON as `envs`.
func TestRegistryEnv_MarshalRoundTrip(t *testing.T) {
	r := ProjectRegistry{}
	r.SetEnvV2("age1p", 338, "prod", RegistryEnv{Cluster: "example", Namespace: "demoapp", MinLevel: 40, Recipient: "age1K"})
	data, _ := r.MarshalJSON2()
	if !strings.Contains(string(data), `"envs"`) || !strings.Contains(string(data), `"namespace": "demoapp"`) {
		t.Fatalf("expected new envs shape:\n%s", data)
	}
	back, err := ParseProjectRegistry(data)
	if err != nil {
		t.Fatal(err)
	}
	if back["age1p"].Envs["prod"].Recipient != "age1K" {
		t.Fatalf("round-trip lost recipient")
	}
}
