package broker

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// v4: a full HandleUnseal via the PAT path where the request identifies
// the project by its PUBKEY (recipient), not the numeric project_id. The broker
// must resolve pubkey → numeric id (for the live members/all check + audit),
// decrypt with UnsealVerifiedByKey, and return the plaintext. This is the
// end-to-end proof the v4 read path works through the real handler.
func TestUnsealV4ByRecipient(t *testing.T) {
	s := newStub()
	srv := s.server(t)
	b, kp := testBroker(t, srv.URL, 412)

	// seal a v4 blob (embeds the pubkey) to the repo recipient
	ct, err := crypto.SealMultiV4([]byte("v4-secret"), []string{kp.Recipient}, kp.Recipient, "DATABASE_URL", crypto.DefaultMinAccessLevel)
	if err != nil {
		t.Fatal(err)
	}

	tok := "glpat-good"
	s.tokenActive[tok] = true
	s.userState[tok] = "active"
	s.userBot[tok] = false
	s.member[tok] = map[int64]bool{412: true}

	// request by RECIPIENT (no project_id)
	body, _ := json.Marshal(map[string]any{
		"recipient":  kp.Recipient,
		"ciphertext": base64.StdEncoding.EncodeToString(ct),
		"name":       "DATABASE_URL",
	})
	r := httptest.NewRequest("POST", "/v1/unseal", strings.NewReader(string(body)))
	r.Header.Set("X-GitLab-Token", tok)
	w := httptest.NewRecorder()
	b.HandleUnseal(w, r)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		PlaintextB64 string `json:"plaintext_b64"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	pt, _ := base64.StdEncoding.DecodeString(resp.PlaintextB64)
	if string(pt) != "v4-secret" {
		t.Fatalf("want v4-secret, got %q", pt)
	}
}

// An unknown recipient (pubkey not in the keystore) is denied 404 — the broker
// can't resolve a numeric id/identity, so it fails closed BEFORE any GitLab call.
func TestUnsealV4UnknownRecipientDenied(t *testing.T) {
	s := newStub()
	srv := s.server(t)
	b, _ := testBroker(t, srv.URL, 412)
	other, _ := crypto.GenerateRepoKey()
	ct, _ := crypto.SealMultiV4([]byte("x"), []string{other.Recipient}, other.Recipient, "K", crypto.DefaultMinAccessLevel)

	body, _ := json.Marshal(map[string]any{
		"recipient":  other.Recipient, // not in the keystore (only 412's key is)
		"ciphertext": base64.StdEncoding.EncodeToString(ct),
		"name":       "K",
	})
	r := httptest.NewRequest("POST", "/v1/unseal", strings.NewReader(string(body)))
	r.Header.Set("X-GitLab-Token", "glpat-good")
	w := httptest.NewRecorder()
	b.HandleUnseal(w, r)
	if w.Code != 404 {
		t.Fatalf("unknown recipient must be 404, got %d: %s", w.Code, w.Body.String())
	}
}

// The live members/all gate still applies to v4: a non-member (404 from GitLab)
// is denied even with a valid recipient + decryptable ciphertext — the pubkey
// identity does NOT bypass the read-side access check (resolved via the numeric
// id the broker derived from the pubkey).
func TestUnsealV4NonMemberDenied(t *testing.T) {
	s := newStub()
	srv := s.server(t)
	b, kp := testBroker(t, srv.URL, 412)
	ct, _ := crypto.SealMultiV4([]byte("v4-secret"), []string{kp.Recipient}, kp.Recipient, "K", crypto.DefaultMinAccessLevel)

	tok := "glpat-good"
	s.tokenActive[tok] = true
	s.userState[tok] = "active"
	s.userBot[tok] = false
	// NOT a member of 412 → members/all returns 404

	body, _ := json.Marshal(map[string]any{
		"recipient":  kp.Recipient,
		"ciphertext": base64.StdEncoding.EncodeToString(ct),
		"name":       "K",
	})
	r := httptest.NewRequest("POST", "/v1/unseal", strings.NewReader(string(body)))
	r.Header.Set("X-GitLab-Token", tok)
	w := httptest.NewRecorder()
	b.HandleUnseal(w, r)
	if w.Code != 403 {
		t.Fatalf("non-member must be 403, got %d: %s", w.Code, w.Body.String())
	}
}
