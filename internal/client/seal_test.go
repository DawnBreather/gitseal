package client

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

func TestLoadRepoConfig(t *testing.T) {
	dir := t.TempDir()
	seald := filepath.Join(dir, ".seald")
	os.MkdirAll(seald, 0755)
	os.WriteFile(filepath.Join(seald, "repo.yaml"),
		[]byte("project_id: 412\nrecipient: age1xyz\n"), 0644)

	rc, err := LoadRepoConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rc.ProjectID != 412 || rc.Recipient != "age1xyz" {
		t.Fatalf("bad repo config: %+v", rc)
	}
}

// SealToFile + the sealed file format round-trips through the crypto package.
func TestSealToFileProducesUnsealableBlob(t *testing.T) {
	kp, _ := crypto.GenerateRepoKey()
	dir := t.TempDir()
	rc := &RepoConfig{ProjectID: 412, Recipient: kp.Recipient}

	if err := SealToFile(dir, rc, "DATABASE_URL", []byte("s3cr3t")); err != nil {
		t.Fatalf("SealToFile: %v", err)
	}
	sf, err := LoadSealedFile(dir, "DATABASE_URL")
	if err != nil {
		t.Fatalf("LoadSealedFile: %v", err)
	}
	if sf.ProjectID != 412 {
		t.Fatalf("sealed file project_id = %d", sf.ProjectID)
	}
	ct, _ := base64.StdEncoding.DecodeString(sf.Ciphertext)
	got, err := crypto.Unseal(ct, []byte(kp.Identity), 412)
	if err != nil || string(got) != "s3cr3t" {
		t.Fatalf("sealed blob did not round-trip: %v / %q", err, got)
	}
}

// Unseal() posts to the broker and decodes plaintext_b64.
func TestUnsealCallsBrokerAndDecodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-GitLab-Token") != "glpat-x" {
			w.WriteHeader(400)
			return
		}
		var req struct {
			ProjectID  int64  `json:"project_id"`
			Ciphertext string `json:"ciphertext"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.ProjectID != 412 {
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"plaintext_b64": base64.StdEncoding.EncodeToString([]byte("revealed")),
		})
	}))
	t.Cleanup(srv.Close)

	pt, err := Unseal(srv.URL, "glpat-x", UnsealTarget{ProjectID: 412}, "DATABASE_URL", []byte("ciphertextbytes"))
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if string(pt) != "revealed" {
		t.Fatalf("want revealed, got %q", pt)
	}
}

func TestUnsealDeniedReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "caller lacks Developer access to project", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	_, err := Unseal(srv.URL, "glpat-x", UnsealTarget{ProjectID: 412}, "X", []byte("ct"))
	if err == nil {
		t.Fatal("expected error on 403")
	}
}

// Unseal must fail fast on an empty ciphertext instead of POSTing empty bytes
// to the broker (which returns a misleading "decrypt failed (wrong repo or
// corrupt)" — the L17 footgun). The guard is client-side, before any network.
func TestUnsealRejectsEmptyCiphertext(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		json.NewEncoder(w).Encode(map[string]string{"plaintext_b64": ""})
	}))
	t.Cleanup(srv.Close)
	_, err := Unseal(srv.URL, "glpat-x", UnsealTarget{ProjectID: 412}, "SOME_KEY", nil)
	if err == nil {
		t.Fatal("expected error on empty ciphertext")
	}
	if called {
		t.Fatal("broker must NOT be called for an empty ciphertext (fail before network)")
	}
}

// LoadSealedFile is the flat `unseal --name X` accessor. A v2 SealedBundle has
// no top-level `ciphertext`, so the old code silently produced an empty
// ciphertext → misleading broker 400 (L17). It must instead detect the v2
// bundle and return an actionable error pointing at the --svc/--env selector.
func TestLoadSealedFileRejectsV2Bundle(t *testing.T) {
	dir := t.TempDir()
	sealed := filepath.Join(dir, ".sealed")
	os.MkdirAll(sealed, 0755)
	v2 := `{
  "kind": "SealedBundle",
  "version": "v2",
  "project_id": 338,
  "recipients": {"human": "age1xyz"},
  "envs": {"prod": {"cluster": "example", "entries": {"JWT_SECRET_KEY": "abc"}}}
}`
	os.WriteFile(filepath.Join(sealed, "auth.app.json"), []byte(v2), 0644)

	_, err := LoadSealedFile(dir, "auth.app")
	if err == nil {
		t.Fatal("expected LoadSealedFile to reject a v2 bundle")
	}
	msg := err.Error()
	if !strings.Contains(msg, "--svc") || !strings.Contains(msg, "--env") {
		t.Fatalf("error should point at the --svc/--env selector, got: %q", msg)
	}
}
