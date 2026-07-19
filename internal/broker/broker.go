// Package broker implements the gitseal in-cluster unseal service.
//
// Security model (the R2/R3/R4 guarantee):
//
// The broker holds the only copies of the per-repo age private keys (KEK-wrapped)
// and NEVER hands them — or a durable decryption capability — to a client. Every
// /v1/unseal call re-derives authorization LIVE from GitLab using the CALLER'S OWN
// PAT, with NO cache of any decision. The handler is a fail-closed allow-list
// state machine: only the single explicit success path returns plaintext; every
// other outcome (401/403/404/429/5xx/redirect/parse-error/timeout) denies.
//
//	A. (optional, flag) verify Cloudflare Access JWT — deferred for v1
//	B. GET /personal_access_tokens/self  -> token active & not revoked
//	C. GET /user                          -> state==active && bot==false (human)
//	D. GET /projects/{id}?min_access_level=30 -> 200 == caller has >=Developer NOW
//	E. unwrap ONLY keys[project_id] via its KEK
//	F. age-decrypt; embedded project_id re-asserted (in crypto.Unseal)
//	G. return plaintext + audit line
package broker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// KeyStore holds per-repo age identities, keyed by project id — the resolved form
// the unseal path consumes directly (: no KEK step). The identities come
// from the broker-owned, out-of-band keystore Secret (never git).
type KeyStore struct {
	Identities map[int64]string // project_id -> "AGE-SECRET-KEY-1…"
}

// Broker is the unseal service.
type Broker struct {
	GitLabBaseURL   string
	Keys            *KeyStore
	Skipped         []string     // key files skipped at load (degraded set — surfaced by /readyz)
	RequireCFAccess bool         // v1: false (deferred). When true, verify CF Access JWT.
	HTTPClient      *http.Client // nil -> default with 3s timeout
	Logger          *slog.Logger // nil -> default

	Registry        *Registry       // project registry (config snapshot) —
	Challenges      *ChallengeStore // SSH challenge nonces (Stage D); nil = SSH auth disabled
	ServiceToken    string          // non-admin GitLab token for member lookups + index reconcile
	Identity        *IdentityIndex  // fp→(uid,pubkey) built from GitLab; nil = use Registry users
	SystemHookToken string          // shared secret for the GitLab system-hook receiver; "" = hook disabled
	reconcileHook   func()          // test seam: overrides the reconcile the hook triggers (nil = real reconcile)

	Recipients    *RecipientRegistry // dynamic (project,env)→materializer recipient, controller-registered
	RegisterToken string             // shared secret for POST /v1/recipient/register; "" = disabled

	// Peer fan-out: the recipient registry is per-pod in-memory soft
	// state, but the broker runs >1 replica behind a Service. A controller POSTs a
	// registration to ONE replica; without fan-out the other replicas serve a stale
	// snapshot → seal round-robins into a split-brain. The receiving replica
	// forwards each (non-forwarded) registration to its peers, discovered by DNS
	// over a HEADLESS Service (all pod IPs) — no k8s API / RBAC. Fan-out is
	// best-effort (controllers re-register every reconcile → a dropped forward
	// self-heals within a poll).
	PeerDNS  string // headless-Service DNS name resolving to all broker pod IPs; "" = fan-out off
	SelfIP   string // this pod's own IP (POD_IP downward API) — excluded from peers
	PeerPort string // port peers listen on (default "8080")

	peerURLs func() []string // test seam; nil → derive from PeerDNS/SelfIP/PeerPort via net.LookupHost

	keyMu    sync.RWMutex // guards Keys/Skipped/draining against concurrent access
	draining bool         // set on SIGTERM → /readyz returns 503 to drain endpoints

	missMu   sync.Mutex // guards lastMiss (on-miss index refresh rate limit)
	lastMiss time.Time  // last on-miss reconcile time (throttle)
}

type unsealRequest struct {
	ProjectID  int64  `json:"project_id"`          // v1-v3: numeric identity
	Recipient  string `json:"recipient,omitempty"` // v4: project pubkey identity
	Ciphertext string `json:"ciphertext"`
	Name       string `json:"name"`
}

func (b *Broker) client() *http.Client {
	if b.HTTPClient != nil {
		return b.HTTPClient
	}
	return &http.Client{
		Timeout: 3 * time.Second,
		// NEVER follow redirects: a GitLab (or MITM) 3xx -> "200 OK" page would
		// otherwise be followed and the final 200 mistaken for authorization
		// success, bypassing the live membership gate (R3). ErrUseLastResponse
		// makes Do() return the 3xx response as-is, which our != 200 checks deny.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (b *Broker) log() *slog.Logger {
	if b.Logger != nil {
		return b.Logger
	}
	return slog.Default()
}

// deny writes a status and an audit line. Never logs token or plaintext.
func (b *Broker) deny(w http.ResponseWriter, code int, projectID int64, reason string) {
	b.log().Info("unseal", "decision", "deny", "code", code, "project_id", projectID, "reason", reason)
	http.Error(w, reason, code)
}

// gitlabGET performs an authenticated GET and returns (statusCode, body, err).
// Any transport error returns err (caller denies).
func (b *Broker) gitlabGET(ctx context.Context, path, token string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", b.GitLabBaseURL+path, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", token)
	req.Header.Set("Accept", "application/json")
	resp, err := b.client().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	// Cap the body at 1 MiB and distinguish a clean EOF from a mid-stream read
	// error: a transport error (truncated/reset connection) must surface as err
	// so the caller denies, never parsing a partial body as a valid response.
	limited := io.LimitReader(resp.Body, 1<<20)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return 0, nil, fmt.Errorf("read body: %w", err)
	}
	return resp.StatusCode, buf, nil
}

// unsealDeadline bounds the whole unseal handler (the 3× sequential GitLab calls
// + decrypt) so a slow/hung GitLab can't pin a connection until the server's
// WriteTimeout kills it mid-response. Comfortably above the per-call client
// timeout (3s) × the calls made, below WriteTimeout (15s).
const unsealDeadline = 12 * time.Second

// HandleUnseal is the fail-closed state machine.
func (b *Broker) HandleUnseal(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), unsealDeadline)
	defer cancel()

	// --- A. Cloudflare Access (deferred for v1; flag-gated) ---
	if b.RequireCFAccess {
		if r.Header.Get("Cf-Access-Jwt-Assertion") == "" {
			b.deny(w, http.StatusForbidden, 0, "missing Cloudflare Access assertion")
			return
		}
		// (full JWT signature+audience verification wired when enabled)
	}

	if r.Method != http.MethodPost {
		b.deny(w, http.StatusMethodNotAllowed, 0, "method not allowed")
		return
	}

	var req unsealRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		b.deny(w, http.StatusBadRequest, 0, "invalid request body")
		return
	}
	// v4: a request may identify the project by its PUBKEY (recipient)
	// instead of the numeric project_id. Resolve pubkey → (identity, numeric id)
	// from the keystore up front, so the auth/members-all/audit path downstream is
	// identical for both. The numeric id is still needed for the live members/all
	// check + audit log. Exactly one identity form is required.
	var v4Identity string // set iff this is a v4 (pubkey-keyed) request
	if req.Recipient != "" {
		id, pid, ok := b.keyForPubkey(req.Recipient)
		if !ok {
			b.deny(w, http.StatusNotFound, 0, "no key for recipient (unknown project pubkey)")
			return
		}
		req.ProjectID = pid // resolved numeric id drives the live authz check below
		v4Identity = id
	}
	if req.ProjectID <= 0 {
		b.deny(w, http.StatusBadRequest, req.ProjectID, "missing project_id or recipient")
		return
	}
	ct, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		b.deny(w, http.StatusBadRequest, req.ProjectID, "invalid ciphertext encoding")
		return
	}

	// --- B/C. Authenticate the caller → user.ID + the token used for the leg-D
	// member lookup. TWO methods converge here:
	// SSH (Stage D): headers X-Seald-Fingerprint/Nonce/Signature. The
	//     signed nonce is non-replayable; the fingerprint resolves to a registered
	//     user_id (authViaSSH). Member lookup uses the broker's OWN non-admin
	//     ServiceToken (the caller has no PAT).
	//   PAT (legacy): X-GitLab-Token — token liveness + /user identity, and the
	//     caller's own token does the member lookup.
	var userID int64
	var lookupToken string
	if fp := r.Header.Get("X-Seald-Fingerprint"); fp != "" {
		uid, err := b.authViaSSH(fp, r.Header.Get("X-Seald-Nonce"), r.Header.Get("X-Seald-Signature"))
		if err != nil {
			b.deny(w, http.StatusUnauthorized, req.ProjectID, "ssh auth failed: "+err.Error())
			return
		}
		if b.ServiceToken == "" {
			b.deny(w, http.StatusServiceUnavailable, req.ProjectID, "ssh auth: broker has no service token for member lookup")
			return
		}
		// review BLOCKER fix: the SSH path must ALSO re-check the account is
		// a live human (leg C), not just resolve identity from the registry. GitLab
		// RETAINS membership rows when a user is BLOCKED, so leg D (members/all) alone
		// still returns an ex-employee's level — a blocked user holding their SSH key
		// would otherwise unseal. Do a LIVE state/bot check with the service token so
		// SSH converges on B/C+D, restoring instant revocation on block/deactivate.
		if err := b.checkUserActive(ctx, b.ServiceToken, uid); err != nil {
			b.deny(w, http.StatusUnauthorized, req.ProjectID, "ssh auth: "+err.Error())
			return
		}
		userID, lookupToken = uid, b.ServiceToken
	} else {
		token := r.Header.Get("X-GitLab-Token")
		if token == "" {
			b.deny(w, http.StatusBadRequest, req.ProjectID, "missing auth (X-Seald-Fingerprint SSH or X-GitLab-Token PAT)")
			return
		}
		// --- B. Token liveness ---
		code, body, err := b.gitlabGET(ctx, "/api/v4/personal_access_tokens/self", token)
		if err != nil {
			b.deny(w, http.StatusServiceUnavailable, req.ProjectID, "gitlab unreachable (token check)")
			return
		}
		if code != 200 {
			b.deny(w, http.StatusUnauthorized, req.ProjectID, "token not active")
			return
		}
		var self struct {
			Active  bool     `json:"active"`
			Revoked bool     `json:"revoked"`
			Scopes  []string `json:"scopes"`
		}
		if json.Unmarshal(body, &self) != nil || !self.Active || self.Revoked {
			b.deny(w, http.StatusUnauthorized, req.ProjectID, "token inactive or revoked")
			return
		}
		// --- C. Identity binding (human, active) ---
		code, body, err = b.gitlabGET(ctx, "/api/v4/user", token)
		if err != nil {
			b.deny(w, http.StatusServiceUnavailable, req.ProjectID, "gitlab unreachable (user check)")
			return
		}
		if code != 200 {
			b.deny(w, http.StatusUnauthorized, req.ProjectID, "cannot resolve user")
			return
		}
		var user struct {
			ID    int64  `json:"id"`
			State string `json:"state"`
			Bot   bool   `json:"bot"`
		}
		if json.Unmarshal(body, &user) != nil || user.State != "active" || user.Bot {
			b.deny(w, http.StatusUnauthorized, req.ProjectID, "user not an active human")
			return
		}
		userID, lookupToken = user.ID, token
	}

	// --- D. Resolve the caller's EFFECTIVE numeric access level on this project,
	// ONCE, via members/all/:user_id (the only reliable check — the
	// min_access_level query param does NOT gate on 15.6.2-ee). Baseline: must be
	// at least Developer. The AUTHORITATIVE per-secret level is re-checked in F
	// against this same number. This live check is IDENTICAL for SSH + PAT auth —
	// instant revocation holds regardless of how the caller authenticated. ---
	callerLvl, err := b.callerLevel(ctx, lookupToken, req.ProjectID, userID)
	if err != nil {
		b.deny(w, http.StatusServiceUnavailable, req.ProjectID, "gitlab unreachable (authz check)")
		return
	}
	if callerLvl < crypto.DefaultMinAccessLevel {
		b.deny(w, http.StatusForbidden, req.ProjectID, "caller lacks Developer access to project")
		return
	}

	// --- E. Resolve ONLY this project's identity ---
	// Read via keyFor (read-locked) so a concurrent hot-reload swap is race-safe.
	// the keystore holds the raw identity directly — no KEK unwrap step.
	// v4: the identity was already resolved from the pubkey above.
	identity := v4Identity
	if identity == "" {
		id, ok := b.keyFor(req.ProjectID)
		if !ok {
			b.deny(w, http.StatusNotFound, req.ProjectID, "no key for project")
			return
		}
		identity = id
	}

	// --- F. Decrypt + re-assert the embedded anti-splice discriminator, returning
	// the EMBEDDED required access level. v1-v3 re-assert the numeric project_id;
	// v4 re-asserts the embedded pubkey == req.Recipient. The plaintext
	// is held but NOT returned until the level check below passes. ---
	var plaintext []byte
	var requiredLevel int
	if req.Recipient != "" {
		plaintext, requiredLevel, err = crypto.UnsealVerifiedByKey(ct, []byte(identity), req.Recipient)
	} else {
		plaintext, requiredLevel, err = crypto.UnsealVerified(ct, []byte(identity), req.ProjectID)
	}
	if err != nil {
		b.deny(w, http.StatusBadRequest, req.ProjectID, "decrypt failed (wrong repo or corrupt)")
		return
	}

	// Enforce the secret's EMBEDDED required level against the caller's real
	// effective level. A Developer (30) who tampered a prod bundle's cleartext
	// to look like level 30 is caught: the AEAD says 40, the caller is 30, we
	// deny — the plaintext never leaves this function.
	if callerLvl < requiredLevel {
		b.deny(w, http.StatusForbidden, req.ProjectID,
			fmt.Sprintf("secret requires access level %d on this project (caller has %d)", requiredLevel, callerLvl))
		return
	}

	// --- G. Respond + audit ---
	b.log().Info("unseal", "decision", "allow", "code", 200,
		"project_id", req.ProjectID, "user_id", userID, "name", req.Name, "level", requiredLevel)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"plaintext_b64": base64.StdEncoding.EncodeToString(plaintext),
	})
}

// callerLevel returns the caller's EFFECTIVE numeric access level on the project
// (0 if not a member). It uses GET /projects/:id/members/all/:user_id, which
// returns the real access_level INCLUDING inherited group membership.
//
// IMPORTANT (learned from a live non-admin test): GitLab 15.6.2-ee's
// GET /projects/:id?min_access_level=N does NOT gate — it returns 200 even when
// the caller is below N — so it is unusable as an authorization check. The
// members/all/:user_id endpoint returns the authoritative numeric level, which
// we compare ourselves. A transport error returns err (fail closed); a 404
// (not a member) is level 0.
func (b *Broker) callerLevel(ctx context.Context, token string, projectID, userID int64) (int, error) {
	path := fmt.Sprintf("/api/v4/projects/%d/members/all/%d", projectID, userID)
	code, body, err := b.gitlabGET(ctx, path, token)
	if err != nil {
		return 0, err
	}
	if code == 404 {
		return 0, nil // not a member
	}
	if code != 200 {
		return 0, fmt.Errorf("members/all returned %d", code)
	}
	var m struct {
		AccessLevel int `json:"access_level"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return 0, fmt.Errorf("parse member: %w", err)
	}
	return m.AccessLevel, nil
}

// checkUserActive is the leg-C-equivalent live account-state gate for the SSH auth
// path (review blocker): GET /users/:id and require state=="active" &&
// !bot. GitLab retains membership rows on BLOCK, so members/all (leg D) alone does
// NOT catch a blocked/deactivated user — this restores instant revocation on the
// SSH path so it converges with the PAT path (which checks /user). Fail-closed:
// transport error / non-200 / non-active / bot → deny. Uses the broker's service
// token (the SSH caller has no PAT). The user representation returned to a
// non-admin token includes `state` + `bot`.
func (b *Broker) checkUserActive(ctx context.Context, token string, userID int64) error {
	code, body, err := b.gitlabGET(ctx, fmt.Sprintf("/api/v4/users/%d", userID), token)
	if err != nil {
		return fmt.Errorf("gitlab unreachable (user state check)")
	}
	if code != 200 {
		return fmt.Errorf("cannot resolve user %d state (%d)", userID, code)
	}
	var u struct {
		State string `json:"state"`
		Bot   bool   `json:"bot"`
	}
	if json.Unmarshal(body, &u) != nil {
		return fmt.Errorf("parse user %d", userID)
	}
	if u.State != "active" {
		return fmt.Errorf("user %d is not active (state=%q) — access revoked", userID, u.State)
	}
	if u.Bot {
		return fmt.Errorf("user %d is a bot — not permitted", userID)
	}
	return nil
}
