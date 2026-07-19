package broker

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// HandleSystemHook receives GitLab instance system-hook POSTs: it
// authenticates the shared X-Gitlab-Token, and on a relevant event
// (key_create/key_destroy/user_add_to_team/user_remove_from_team) triggers an
// index reconcile — the latency layer that gives instant key-revocation over the
// poll. Best-effort: reconcile is still the source of truth.
func TestHandleSystemHook_AuthAndDispatch(t *testing.T) {
	reconciled := 0
	b := &Broker{
		Identity:        NewIdentityIndex(),
		SystemHookToken: "shhh",
		// inject the reconcile so the test doesn't need GitLab
		reconcileHook: func() { reconciled++ },
	}

	post := func(token, body string) int {
		r := httptest.NewRequest("POST", "/v1/gitlab/system-hook", strings.NewReader(body))
		if token != "" {
			r.Header.Set("X-Gitlab-Token", token)
		}
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		b.HandleSystemHook(w, r)
		return w.Code
	}

	// missing token → 401, no reconcile
	if code := post("", `{"event_name":"key_destroy"}`); code != 401 {
		t.Fatalf("missing token want 401, got %d", code)
	}
	// wrong token → 401
	if code := post("nope", `{"event_name":"key_destroy"}`); code != 401 {
		t.Fatalf("wrong token want 401, got %d", code)
	}
	if reconciled != 0 {
		t.Fatalf("no reconcile should happen on auth failure, got %d", reconciled)
	}

	// valid token + key_destroy → 200 + reconcile triggered
	if code := post("shhh", `{"event_name":"key_destroy","username":"mark"}`); code != 200 {
		t.Fatalf("valid key_destroy want 200, got %d", code)
	}
	if reconciled != 1 {
		t.Fatalf("key_destroy must trigger reconcile, got %d", reconciled)
	}

	// valid token + irrelevant event (project_create) → 200 but NO reconcile
	if code := post("shhh", `{"event_name":"project_create"}`); code != 200 {
		t.Fatalf("irrelevant event want 200, got %d", code)
	}
	if reconciled != 1 {
		t.Fatalf("irrelevant event must NOT reconcile, got %d", reconciled)
	}

	// key_create + membership events also reconcile
	for _, ev := range []string{"key_create", "user_add_to_team", "user_remove_from_team"} {
		post("shhh", `{"event_name":"`+ev+`"}`)
	}
	if reconciled != 4 {
		t.Fatalf("relevant events must each reconcile: got %d want 4", reconciled)
	}
}

// When no SystemHookToken is configured, the endpoint is disabled (503/501) — never
// an unauthenticated open door on a decrypting service.
func TestHandleSystemHook_DisabledWithoutToken(t *testing.T) {
	b := &Broker{Identity: NewIdentityIndex()}
	r := httptest.NewRequest("POST", "/v1/gitlab/system-hook", strings.NewReader(`{"event_name":"key_destroy"}`))
	r.Header.Set("X-Gitlab-Token", "anything")
	w := httptest.NewRecorder()
	b.HandleSystemHook(w, r)
	if w.Code == 200 {
		t.Fatal("hook must be disabled (not 200) when no SystemHookToken is set")
	}
}

var _ = http.MethodPost
