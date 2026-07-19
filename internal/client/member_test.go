package client

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// --- project member level lookup ------------------------------------------------
//
// ProjectMemberLevel returns the caller-independent EFFECTIVE access level of a
// given user on a project, via GET /projects/:id/members/all/:user_id (the
// authoritative endpoint — the broker learned the hard way that
// ?min_access_level=N does NOT gate on this GitLab version). 404 → level 0 (not a
// member). Transport / non-200 → error, so the caller can fail closed.

func TestProjectMemberLevel_200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/projects/338/members/all/42" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Header.Get("PRIVATE-TOKEN") != "tok" {
			t.Errorf("missing/wrong token header: %q", r.Header.Get("PRIVATE-TOKEN"))
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"id":42,"username":"dev","access_level":40}`))
	}))
	defer srv.Close()

	lvl, err := ProjectMemberLevelAt(srv.URL, "tok", 338, 42)
	if err != nil {
		t.Fatalf("ProjectMemberLevelAt: %v", err)
	}
	if lvl != 40 {
		t.Fatalf("level = %d, want 40", lvl)
	}
}

func TestProjectMemberLevel_404IsZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte(`{"message":"404 Not found"}`))
	}))
	defer srv.Close()

	lvl, err := ProjectMemberLevelAt(srv.URL, "tok", 338, 999)
	if err != nil {
		t.Fatalf("404 should be (0,nil), got err %v", err)
	}
	if lvl != 0 {
		t.Fatalf("level for non-member = %d, want 0", lvl)
	}
}

func TestProjectMemberLevel_500IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	if _, err := ProjectMemberLevelAt(srv.URL, "tok", 338, 42); err == nil {
		t.Fatal("500 must return an error (so the caller fails closed), got nil")
	}
}
