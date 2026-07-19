package broker

import (
	"encoding/json"
	"io"
	"net/http"
)

// systemHookEvents are the GitLab instance system-hook events that change the
// identity index: SSH keys (create/destroy) and project membership. Anything else
// (project_create, push, …) is acknowledged but ignored.
var systemHookEvents = map[string]bool{
	"key_create":            true,
	"key_destroy":           true, // → instant key-revocation (the poll-over win)
	"user_add_to_team":      true,
	"user_remove_from_team": true,
}

// HandleSystemHook receives GitLab instance system-hook POSTs and, on a
// relevant event, reconciles the identity index — the latency layer over the poll
// that gives INSTANT key-revocation (key_destroy) + near-instant onboarding
// (key_create). Best-effort: the poll remains the source of truth, so a missed or
// spoofed-but-rejected hook only affects latency, never correctness.
//
// SECURITY (a network decrypting service must not expose an open endpoint):
//   - disabled unless SystemHookToken is configured (503);
//   - the shared X-Gitlab-Token secret must match exactly (401) — this is the same
//     token set on the GitLab hook; GitLab sends it on every delivery;
//   - the body is parsed only for event_name (no trust in its contents — we
//     RECONCILE from GitLab rather than apply the payload's claims, so a forged
//     body can at worst trigger a rate-limited reconcile, never inject identity).
func (b *Broker) HandleSystemHook(w http.ResponseWriter, r *http.Request) {
	if b.SystemHookToken == "" {
		http.Error(w, "system hook not enabled", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// constant-time-ish token check (exact match; tokens are high-entropy secrets).
	if r.Header.Get("X-Gitlab-Token") != b.SystemHookToken {
		b.log().Warn("system-hook: rejected (bad/missing token)")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var ev struct {
		EventName string `json:"event_name"`
	}
	_ = json.Unmarshal(body, &ev) // an unparseable body → no event → ack + ignore

	relevant := systemHookEvents[ev.EventName]
	// Observability: a receive endpoint on a decrypting service must not be a black
	// box (anti-silent-health). Log every authenticated delivery + whether it drove
	// a reconcile, so hook connectivity is visible without guessing.
	b.log().Info("system-hook received", "event", ev.EventName, "reconcile", relevant)
	if relevant {
		b.triggerReconcile()
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// triggerReconcile runs the index reconcile the hook asks for. The reconcileHook
// seam lets tests observe it without GitLab; in production it does a real,
// rate-limited reconcile (reusing the on-miss throttle so a hook storm can't
// hammer GitLab).
func (b *Broker) triggerReconcile() {
	if b.reconcileHook != nil {
		b.reconcileHook()
		return
	}
	// Reuse onMissRefresh: it is already rate-limited + best-effort, exactly the
	// semantics we want for hook-driven reconciles.
	b.onMissRefresh()
}
