package client

import (
	"os"
	"path/filepath"
	"testing"
)

// ResolvePAT prefers $GITLAB_TOKEN, then falls back to the glab config file.
// (The `glab auth token` exec path is covered by integration, not unit, tests.)
func TestResolvePATPrefersEnv(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "glpat-from-env")
	got, src, err := ResolvePAT("gitlab.example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "glpat-from-env" {
		t.Fatalf("want env token, got %q", got)
	}
	if src != "env" {
		t.Fatalf("want source env, got %q", src)
	}
}

func TestResolvePATFromGlabConfig(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "") // force fallback
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yml")
	os.WriteFile(cfg, []byte(`hosts:
  gitlab.example.com:
    token: glpat-from-config
    api_protocol: https
`), 0600)

	got, src, err := ResolvePAT("gitlab.example.com", cfg)
	if err != nil {
		t.Fatalf("ResolvePAT: %v", err)
	}
	if got != "glpat-from-config" {
		t.Fatalf("want config token, got %q", got)
	}
	if src != "glab-config" {
		t.Fatalf("want source glab-config, got %q", src)
	}
}

func TestResolvePATNotFound(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "")
	_, _, err := ResolvePAT("gitlab.example.com", "/nonexistent/config.yml")
	if err == nil {
		t.Fatal("expected error when no token found anywhere")
	}
}
