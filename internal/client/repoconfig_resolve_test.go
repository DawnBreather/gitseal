package client

import (
	"os"
	"path/filepath"
	"testing"
)

// ResolveRepoConfig merges a (possibly recipient-only, v4) repo.yaml with the
// broker registry snapshot: repo.yaml provides the recipient identity; the
// snapshot fills project_id / clusters / env_cluster / env_min_level. A repo.yaml
// that already carries those fields (v2/v3 era) is used as-is (no fetch needed).
func TestResolveRepoConfig_FillsFromSnapshot(t *testing.T) {
	srv := snapshotServer(t, nil)
	defer srv.Close()

	// a v4 recipient-only repo.yaml
	root := t.TempDir()
	seald := filepath.Join(root, ".seald")
	os.MkdirAll(seald, 0o755)
	os.WriteFile(filepath.Join(seald, "repo.yaml"), []byte("recipient: "+snapPub+"\n"), 0o644)

	rc, err := ResolveRepoConfig(root, srv.URL, filepath.Join(t.TempDir(), "c.json"))
	if err != nil {
		t.Fatalf("ResolveRepoConfig: %v", err)
	}
	if rc.Recipient != snapPub || rc.ProjectID != 338 {
		t.Fatalf("identity wrong: recip=%q pid=%d", rc.Recipient, rc.ProjectID)
	}
	if rc.EnvCluster["prod"] != "example" || rc.EnvRecipient["prod"] != "age1G" {
		t.Fatalf("operational fields not filled: %+v", rc)
	}
	if rc.MinLevelForEnv("prod") != 40 || rc.MinLevelForEnv("staging") != 30 {
		t.Fatalf("env_min_level not filled: %+v", rc.EnvMinLevel)
	}
}

// A repo.yaml that already carries the operational fields (a v2/v3-era repo, or a
// pinned override) is returned verbatim — the snapshot is not consulted, so an
// offline user with a full repo.yaml still works with no broker.
func TestResolveRepoConfig_SelfContainedNoFetch(t *testing.T) {
	root := t.TempDir()
	seald := filepath.Join(root, ".seald")
	os.MkdirAll(seald, 0o755)
	full := "project_id: 338\nrecipient: " + snapPub + "\n" +
		"clusters:\n  example: age1G\nenv_cluster:\n  prod: example\nenv_min_level:\n  prod: 40\n"
	os.WriteFile(filepath.Join(seald, "repo.yaml"), []byte(full), 0o644)

	// broker URL is deliberately bogus — must NOT be contacted.
	rc, err := ResolveRepoConfig(root, "http://127.0.0.1:1", filepath.Join(t.TempDir(), "c.json"))
	if err != nil {
		t.Fatalf("self-contained repo.yaml must resolve with no fetch: %v", err)
	}
	if rc.ProjectID != 338 || rc.EnvCluster["prod"] != "example" {
		t.Fatalf("self-contained fields lost: %+v", rc)
	}
}
