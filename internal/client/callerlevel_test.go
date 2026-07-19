package client

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// CallerProjectLevel resolves the token's own user (/user) then that user's
// effective project level (members/all) — the numeric level `env list` needs to
// decide can-seal per env. Uses the AUTHORITATIVE members/all endpoint (the
// ?min_access_level query is unreliable on this GitLab, per the broker lesson).
func TestCallerProjectLevel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v4/user":
			w.Write([]byte(`{"id":87,"username":"won","state":"active"}`))
		case strings.HasPrefix(r.URL.Path, "/api/v4/projects/338/members/all/87"):
			w.Write([]byte(`{"id":87,"access_level":50}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	lvl, err := callerProjectLevelAt(srv.URL, "tok", 338)
	if err != nil {
		t.Fatalf("CallerProjectLevel: %v", err)
	}
	if lvl != 50 {
		t.Fatalf("level = %d, want 50", lvl)
	}
}

// A non-member (members/all 404) resolves to level 0, not an error — env list
// should still render (all envs read-only), not blow up.
func TestCallerProjectLevel_NonMember(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v4/user" {
			w.Write([]byte(`{"id":99,"username":"x","state":"active"}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	lvl, err := callerProjectLevelAt(srv.URL, "tok", 338)
	if err != nil || lvl != 0 {
		t.Fatalf("non-member want (0,nil), got (%d,%v)", lvl, err)
	}
}
