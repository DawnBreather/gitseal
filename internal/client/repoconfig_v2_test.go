package client

import (
	"os"
	"path/filepath"
	"testing"
)

// --- Task 2.1: repo.yaml v2 clusters + env→cluster registry --------------------
//
// A v2 repo.yaml adds a `clusters` map (name → age recipient) and an
// `env_cluster` map (env → cluster name), so the authoring tools can resolve
// "which cluster (and thus which recipient) does env E seal to?". v1 repo.yaml
// (no clusters/env_cluster) must still load unchanged.

func writeRepoYAML(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	seald := filepath.Join(dir, ".seald")
	if err := os.MkdirAll(seald, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(seald, "repo.yaml"), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRepoConfigV2ClusterForEnv(t *testing.T) {
	dir := writeRepoYAML(t, `project_id: 338
recipient: age1human
clusters:
  example: age1G
  staging: age1S
env_cluster:
  prod: example
  preprod: example
  staging: staging
`)

	rc, err := LoadRepoConfig(dir)
	if err != nil {
		t.Fatalf("LoadRepoConfig: %v", err)
	}
	if rc.ProjectID != 338 || rc.Recipient != "age1human" {
		t.Fatalf("v1 fields lost: %+v", rc)
	}

	name, recip, err := rc.ClusterForEnv("prod")
	if err != nil {
		t.Fatalf("ClusterForEnv(prod): %v", err)
	}
	if name != "example" || recip != "age1G" {
		t.Fatalf("ClusterForEnv(prod) = (%q,%q), want (example, age1G)", name, recip)
	}

	// preprod and prod share the same physical cluster key (intended).
	name, recip, err = rc.ClusterForEnv("preprod")
	if err != nil || name != "example" || recip != "age1G" {
		t.Fatalf("ClusterForEnv(preprod) = (%q,%q,%v), want (example, age1G, nil)", name, recip, err)
	}

	name, recip, err = rc.ClusterForEnv("staging")
	if err != nil || name != "staging" || recip != "age1S" {
		t.Fatalf("ClusterForEnv(staging) = (%q,%q,%v), want (staging, age1S, nil)", name, recip, err)
	}

	// unknown env → clear error, no recipient.
	if _, _, err := rc.ClusterForEnv("bogus"); err == nil {
		t.Fatal("ClusterForEnv(bogus): expected error, got nil")
	}
}

// A cluster named in env_cluster but absent from the clusters map is a
// misconfiguration; ClusterForEnv must error rather than return an empty
// recipient (which would seal to nothing / a garbage recipient later).
func TestRepoConfigV2MissingClusterRecipient(t *testing.T) {
	dir := writeRepoYAML(t, `project_id: 338
recipient: age1human
clusters:
  example: age1G
env_cluster:
  prod: example
  staging: staging
`)
	rc, err := LoadRepoConfig(dir)
	if err != nil {
		t.Fatalf("LoadRepoConfig: %v", err)
	}
	if _, _, err := rc.ClusterForEnv("staging"); err == nil {
		t.Fatal("ClusterForEnv(staging): expected error (cluster recipient missing), got nil")
	}
}

// v1-only repo.yaml (no clusters/env_cluster) still loads; ClusterForEnv errors
// because no registry is present, but LoadRepoConfig itself succeeds.
func TestRepoConfigV1StillLoads(t *testing.T) {
	dir := writeRepoYAML(t, "project_id: 412\nrecipient: age1xyz\n")

	rc, err := LoadRepoConfig(dir)
	if err != nil {
		t.Fatalf("LoadRepoConfig(v1): %v", err)
	}
	if rc.ProjectID != 412 || rc.Recipient != "age1xyz" {
		t.Fatalf("bad v1 repo config: %+v", rc)
	}
	if rc.Clusters != nil || rc.EnvCluster != nil {
		t.Fatalf("v1 repo.yaml should have nil clusters/env_cluster: %+v", rc)
	}
	if _, _, err := rc.ClusterForEnv("prod"); err == nil {
		t.Fatal("ClusterForEnv on v1 repo.yaml: expected error (no registry), got nil")
	}
}
