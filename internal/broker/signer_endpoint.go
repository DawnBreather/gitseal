package broker

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
)

// signerResolveResponse is what /v1/signer/resolve returns: whether the fingerprint
// is a registered user, and (if a project_id is given) that user's LIVE effective
// access level on the project. The CI write-authz gate uses this to enforce
// per-env-section signatures without ever holding the user registry itself.
type signerResolveResponse struct {
	Registered bool   `json:"registered"`
	PubKey     string `json:"pubkey,omitempty"`     // authorized-key line, for offline sig verify
	UserID     int64  `json:"user_id,omitempty"`    // gitlab user id
	LiveLevel  int    `json:"live_level,omitempty"` // effective level on ?project_id
}

// HandleSignerResolve resolves a signer fingerprint (query ?fingerprint=…&project_id=…)
// to (registered?, pubkey, live project level). It is READ-only and returns only
// what the CI gate needs; the fingerprint→user_id map + the pubkey are already
// "public enough" (a fingerprint is not a secret), and the live level is a fresh
// GitLab members/all check via the broker's own service token. This lets the write
// gate enforce signatures + authorization while the user registry stays broker-held
// (not in the public snapshot). Fail-closed: unknown fingerprint → registered:false.
func (b *Broker) HandleSignerResolve(w http.ResponseWriter, r *http.Request) {
	if b.Registry == nil && b.Identity == nil {
		http.Error(w, "signer resolution not enabled", http.StatusNotImplemented)
		return
	}
	fp := r.URL.Query().Get("fingerprint")
	if fp == "" {
		http.Error(w, "missing fingerprint", http.StatusBadRequest)
		return
	}
	resp := signerResolveResponse{}
	uid, keyLine, ok := b.resolveSigner(fp) // index-first, registry fallback
	if !ok {
		writeJSON(w, resp) // registered:false
		return
	}
	resp.Registered = true
	resp.UserID = uid
	resp.PubKey = keyLine
	// live level if a project is named + we have a service token to ask GitLab.
	if pidStr := r.URL.Query().Get("project_id"); pidStr != "" && b.ServiceToken != "" {
		var pid int64
		if pid, _ = strconv.ParseInt(pidStr, 10, 64); pid > 0 {
			ctx, cancel := context.WithTimeout(r.Context(), unsealDeadline)
			defer cancel()
			if lvl, err := b.callerLevel(ctx, b.ServiceToken, pid, uid); err == nil {
				resp.LiveLevel = lvl
			} else {
				// live check failed → fail closed: report level 0 (deny downstream).
				resp.LiveLevel = 0
			}
		}
	}
	writeJSON(w, resp)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}
