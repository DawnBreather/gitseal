package broker

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// the broker's ProjectEntry must carry the first-class Envs shape
// ({cluster, namespace, min_level, recipient}) so the snapshot it serves to
// seal/verify/env-list clients has per-env recipients + namespaces. It must also
// back-compat-parse the legacy (env_cluster/cluster_recipients) shape.
func TestProjectEntry_EnvsShape(t *testing.T) {
	// new-shape projects.json → parses into Envs, snapshot re-serializes it.
	newShape := `{"age1p":{"project_id":338,"envs":{
	  "prod":{"cluster":"example","namespace":"demoapp","min_level":40,"recipient":"age1prodK"},
	  "preprod":{"cluster":"example","namespace":"demoapp-preprod","min_level":40,"recipient":"age1preprodK"}}}}`
	var reg map[string]ProjectEntry
	if err := json.Unmarshal([]byte(newShape), &reg); err != nil {
		t.Fatalf("parse new shape: %v", err)
	}
	e := reg["age1p"]
	if e.Envs["prod"].Recipient != "age1prodK" || e.Envs["prod"].Namespace != "demoapp" {
		t.Fatalf("prod env wrong: %+v", e.Envs["prod"])
	}
	if e.Envs["prod"].Recipient == e.Envs["preprod"].Recipient {
		t.Fatal("prod/preprod must keep distinct recipients through the broker")
	}

	// the snapshot endpoint serves the envs shape.
	b := &Broker{Registry: &Registry{Projects: reg}}
	rr := httptest.NewRecorder()
	b.HandleRegistrySnapshot(rr, httptest.NewRequest("GET", "/v1/registry/snapshot", nil))
	var snap struct {
		Projects map[string]ProjectEntry `json:"projects"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
		t.Fatalf("snapshot json: %v", err)
	}
	if snap.Projects["age1p"].Envs["prod"].Recipient != "age1prodK" {
		t.Fatalf("snapshot lost per-env recipient: %s", rr.Body.String())
	}
}

// Legacy-shape projects.json still parses (back-compat) — envs derived from the
// cluster maps (recipient = the shared cluster key).
func TestProjectEntry_LegacyBackCompat(t *testing.T) {
	legacy := `{"age1p":{"project_id":338,
	  "env_cluster":{"prod":"example"},"env_min_level":{"prod":40},
	  "cluster_recipients":{"example":"age1G"}}}`
	var reg map[string]ProjectEntry
	if err := json.Unmarshal([]byte(legacy), &reg); err != nil {
		t.Fatalf("parse legacy: %v", err)
	}
	if reg["age1p"].Envs["prod"].Recipient != "age1G" {
		t.Fatalf("legacy back-compat: prod recipient = %q (want age1G)", reg["age1p"].Envs["prod"].Recipient)
	}
}
