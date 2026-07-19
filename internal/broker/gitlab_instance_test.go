//go:build instance

// Instance-pinned tests: run ONLY against the real gitlab.example.com with a
// live token, to confirm the load-bearing membership semantics the unit stubs
// assume. Run with:  go test -tags instance ./internal/broker/ -run Instance
//
//	GITLAB_URL=https://gitlab.example.com GITLAB_TOKEN=... SEALD_TEST_PROJECT=336
package broker

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"
)

func instanceCfg(t *testing.T) (url, token string, project int64) {
	t.Helper()
	url = os.Getenv("GITLAB_URL")
	token = os.Getenv("GITLAB_TOKEN")
	p := os.Getenv("SEALD_TEST_PROJECT")
	if url == "" || token == "" || p == "" {
		t.Skip("set GITLAB_URL, GITLAB_TOKEN, SEALD_TEST_PROJECT to run instance tests")
	}
	project, _ = strconv.ParseInt(p, 10, 64)
	return
}

// The authz endpoint must return 200 when the caller has >= Developer on the
// project (the whole gate depends on this exact behavior on 15.6.2-ee).
func TestInstanceMembershipDeveloperAllows(t *testing.T) {
	url, token, project := instanceCfg(t)
	b := &Broker{GitLabBaseURL: url}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	code, _, err := b.gitlabGET(ctx, "/api/v4/projects/"+strconv.FormatInt(project, 10)+"?min_access_level=30", token)
	if err != nil {
		t.Fatalf("gitlabGET: %v", err)
	}
	if code != 200 {
		t.Fatalf("expected 200 for a Developer+ caller on project %d, got %d", project, code)
	}
}

// A project id the caller is NOT a member of (and is not admin for) must 404.
// Uses SEALD_TEST_NONMEMBER_PROJECT; skipped if not set (admin tokens see all).
func TestInstanceMembershipNonMemberDenies(t *testing.T) {
	url, token, _ := instanceCfg(t)
	np := os.Getenv("SEALD_TEST_NONMEMBER_PROJECT")
	if np == "" {
		t.Skip("set SEALD_TEST_NONMEMBER_PROJECT (a project this token canNOT access; note admin tokens see all)")
	}
	b := &Broker{GitLabBaseURL: url}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	code, _, err := b.gitlabGET(ctx, "/api/v4/projects/"+np+"?min_access_level=30", token)
	if err != nil {
		t.Fatalf("gitlabGET: %v", err)
	}
	if code != 404 {
		t.Fatalf("expected 404 for a non-member project, got %d (is this token an admin?)", code)
	}
}

// Token liveness + identity shape must match what the broker parses.
func TestInstanceTokenAndUserShape(t *testing.T) {
	url, token, _ := instanceCfg(t)
	b := &Broker{GitLabBaseURL: url}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	code, body, err := b.gitlabGET(ctx, "/api/v4/personal_access_tokens/self", token)
	if err != nil || code != 200 {
		t.Fatalf("self: code=%d err=%v", code, err)
	}
	if !containsAll(string(body), `"active"`, `"revoked"`, `"scopes"`) {
		t.Fatalf("self response missing expected fields: %s", body)
	}
	code, body, err = b.gitlabGET(ctx, "/api/v4/user", token)
	if err != nil || code != 200 {
		t.Fatalf("user: code=%d err=%v", code, err)
	}
	if !containsAll(string(body), `"id"`, `"state"`, `"bot"`) {
		t.Fatalf("user response missing expected fields: %s", body)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
