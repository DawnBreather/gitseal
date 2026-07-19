package crypto

import (
	"strings"
	"testing"
)

// FINDING 5 (high, R4): the embedded project_id parser must take the FIRST
// gitseal-project-id header (the one Seal writes) and stop. A crafted secret body
// or a second injected header line must not be able to override the bound id.
// Since the envelope is inside the age AEAD, only someone who can seal (has the
// public key) could inject — but defense in depth: parsing must be deterministic.
func TestUnsealFirstProjectIDHeaderWins(t *testing.T) {
	kp, _ := GenerateRepoKey()
	// Seal a secret whose *body* itself contains a fake header line trying to
	// claim a different project_id. The real header (project 100) must win.
	body := []byte("gitseal-project-id:999\nactual-secret")
	ct, err := Seal(body, kp.Recipient, 100, "X")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Unseal as project 100 must succeed (real header wins, body is opaque).
	got, err := Unseal(ct, []byte(kp.Identity), 100)
	if err != nil {
		t.Fatalf("Unseal as 100 should succeed: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("body corrupted: got %q", got)
	}
	// Unseal as project 999 (the injected value) must FAIL — the body line must
	// not be honored as the binding id.
	if _, err := Unseal(ct, []byte(kp.Identity), 999); err == nil {
		t.Fatal("a project-id line in the BODY must not override the bound header (R4)")
	}
}

// FINDING (low): non-positive embedded project_id is rejected.
func TestUnsealRejectsNonPositiveProjectID(t *testing.T) {
	kp, _ := GenerateRepoKey()
	// Seal will be asked to bind 0 — Seal should refuse, or Unseal must reject.
	_, err := Seal([]byte("x"), kp.Recipient, 0, "X")
	if err == nil {
		t.Fatal("Seal must refuse project_id <= 0")
	}
	if !strings.Contains(err.Error(), "project") {
		t.Fatalf("expected project-id validation error, got %v", err)
	}
}
