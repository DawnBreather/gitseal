package broker

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// FINDING 1/3 (critical/high, R3 + fail-closed): the broker's HTTP client must
// NOT follow redirects. A GitLab (or MITM) 302 -> "200 OK page" would otherwise
// be followed and the final 200 treated as authorization success, bypassing the
// live membership gate. Every GitLab call must treat a 3xx as deny.
func TestUnsealDeniesOnRedirect(t *testing.T) {
	// authz endpoint 302-redirects to a page that returns 200.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/personal_access_tokens/self", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"active":true,"revoked":false,"scopes":["read_api"]}`))
	})
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"id":7,"state":"active","bot":false}`))
	})
	mux.HandleFunc("/evil-200", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"id":412,"name":"repo"}`))
	})
	mux.HandleFunc("/api/v4/projects/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/evil-200", http.StatusFound) // 302
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	b, kp := testBroker(t, srv.URL, 412)
	ct, _ := crypto.Seal([]byte("x"), kp.Recipient, 412, "X")
	w := unsealReq(t, b, "glpat-x", 412, ct)
	if w.Code == 200 {
		t.Fatalf("a 302 on the authz check MUST NOT be followed to a 200 (R3 bypass); got %d", w.Code)
	}
}

// FINDING 4 (high, fail-closed): a 200 with malformed/truncated JSON on the
// token-liveness or user check must deny, not be treated as a valid active human.
func TestUnsealDeniesOnMalformedJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/personal_access_tokens/self", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"active":true,"revoked":false,"scopes":["read_api"]}`))
	})
	// /user returns 200 but a truncated body -> ID stays 0, state empty.
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"id":`)) // truncated
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	b, kp := testBroker(t, srv.URL, 412)
	ct, _ := crypto.Seal([]byte("x"), kp.Recipient, 412, "X")
	w := unsealReq(t, b, "glpat-x", 412, ct)
	if w.Code == 200 {
		t.Fatalf("malformed /user body must deny, got %d", w.Code)
	}
}

// FINDING 4b (high): a 200 /user with id=0 / empty state (zero values) must deny.
func TestUnsealDeniesOnZeroValueUser(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/personal_access_tokens/self", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"active":true,"revoked":false,"scopes":["read_api"]}`))
	})
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`)) // valid JSON, all zero values
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	b, kp := testBroker(t, srv.URL, 412)
	ct, _ := crypto.Seal([]byte("x"), kp.Recipient, 412, "X")
	w := unsealReq(t, b, "glpat-x", 412, ct)
	if w.Code == 200 {
		t.Fatalf("zero-value user (id=0, empty state) must deny, got %d", w.Code)
	}
}
