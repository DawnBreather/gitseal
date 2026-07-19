package broker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// REGRESSION (found via live non-admin test): GitLab 15.6.2-ee's
// GET /projects/:id?min_access_level=N does NOT gate — it returns 200 even when
// the caller is below N. The authoritative check is
// GET /projects/:id/members/all/:user_id → numeric access_level comparison.
// b.callerLevel must return the user's EFFECTIVE numeric level.
func TestCallerLevelFromMembersEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	// members/all/:uid returns the effective access_level
	mux.HandleFunc("/api/v4/projects/337/members/all/233", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"id": 233, "access_level": 30})
	})
	// non-member → 404
	mux.HandleFunc("/api/v4/projects/337/members/all/999", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	b := &Broker{GitLabBaseURL: srv.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lvl, err := b.callerLevel(ctx, "tok", 337, 233)
	if err != nil {
		t.Fatalf("callerLevel: %v", err)
	}
	if lvl != 30 {
		t.Fatalf("want effective level 30, got %d", lvl)
	}
	// a Developer (30) must NOT satisfy a level-40 requirement
	if lvl >= 40 {
		t.Fatal("level 30 must not satisfy 40")
	}

	// non-member → level 0 (deny everything)
	lvl0, err := b.callerLevel(ctx, "tok", 337, 999)
	if err != nil {
		t.Fatalf("callerLevel(nonmember): %v", err)
	}
	if lvl0 != 0 {
		t.Fatalf("non-member must be level 0, got %d", lvl0)
	}
}
