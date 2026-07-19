package broker

import (
	"strings"
	"testing"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// v2: the broker enforces the access level EMBEDDED in the ciphertext, not the
// level the client claims. The stub's member map is now level-aware via a small
// extension: we model GitLab's min_access_level check by storing the caller's
// actual level and answering 200 iff actual >= requested.

// A Maintainer (level 40) CAN unseal a level-40 (prod) secret.
func TestUnsealProdAllowsMaintainer(t *testing.T) {
	s := newStub()
	srv := s.serverWithLevels(t)
	b, kp := testBroker(t, srv.URL, 412)
	ct, _ := crypto.SealWithLevel([]byte("prod"), kp.Recipient, 412, "DB", 40)

	tok := "glpat-maint"
	s.tokenActive[tok] = true
	s.userState[tok] = "active"
	s.level[tok] = map[int64]int{412: 40} // Maintainer
	w := unsealReq(t, b, tok, 412, ct)
	if w.Code != 200 {
		t.Fatalf("Maintainer must unseal a level-40 secret, got %d: %s", w.Code, w.Body.String())
	}
}

// A Developer (level 30) CANNOT unseal a level-40 secret — even though they pass
// the baseline Developer check. This is the core v2 guarantee.
func TestUnsealProdDeniesDeveloper(t *testing.T) {
	s := newStub()
	srv := s.serverWithLevels(t)
	b, kp := testBroker(t, srv.URL, 412)
	ct, _ := crypto.SealWithLevel([]byte("prod"), kp.Recipient, 412, "DB", 40)

	tok := "glpat-dev"
	s.tokenActive[tok] = true
	s.userState[tok] = "active"
	s.level[tok] = map[int64]int{412: 30} // Developer only
	w := unsealReq(t, b, tok, 412, ct)
	if w.Code != 403 {
		t.Fatalf("Developer must NOT unseal a level-40 secret, got %d", w.Code)
	}
}

// DOWNGRADE ATTACK: a Developer crafts a request claiming the bundle is level 30,
// but the ciphertext was sealed at level 40. The broker must use the EMBEDDED
// level (40), re-check, and deny — never return the plaintext.
func TestUnsealDowngradeAttackDenied(t *testing.T) {
	s := newStub()
	srv := s.serverWithLevels(t)
	b, kp := testBroker(t, srv.URL, 412)
	// sealed at 40
	ct, _ := crypto.SealWithLevel([]byte("prod-secret"), kp.Recipient, 412, "DB", 40)

	tok := "glpat-dev"
	s.tokenActive[tok] = true
	s.userState[tok] = "active"
	s.level[tok] = map[int64]int{412: 30} // Developer
	// The client can't influence the embedded level; the broker reads 40 from
	// the AEAD after decrypt and re-checks. Developer (30) < 40 → deny.
	w := unsealReq(t, b, tok, 412, ct)
	if w.Code == 200 {
		t.Fatalf("DOWNGRADE: a Developer must not extract a level-40 secret, got 200")
	}
	if w.Code != 403 {
		t.Fatalf("downgrade attempt should be 403, got %d", w.Code)
	}
	// and the secret must not appear in the response
	if strings.Contains(w.Body.String(), "prod-secret") {
		t.Fatal("plaintext leaked in a denied downgrade response")
	}
}

// A legacy (no-level) blob still works at the default Developer level.
func TestUnsealLegacyBlobDeveloperOK(t *testing.T) {
	s := newStub()
	srv := s.serverWithLevels(t)
	b, kp := testBroker(t, srv.URL, 412)
	ct, _ := crypto.Seal([]byte("legacy"), kp.Recipient, 412, "DB") // no level → 30

	tok := "glpat-dev"
	s.tokenActive[tok] = true
	s.userState[tok] = "active"
	s.level[tok] = map[int64]int{412: 30}
	w := unsealReq(t, b, tok, 412, ct)
	if w.Code != 200 {
		t.Fatalf("legacy blob must work for a Developer, got %d", w.Code)
	}
}
