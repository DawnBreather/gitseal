package broker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// --- SSH challenge nonce store (Stage D) -----------------------------
//
// Human→broker auth is a challenge-response: the broker issues a random, single-use,
// short-TTL nonce; the caller SSH-signs it (private key never leaves them) and
// presents (fingerprint, nonce, signature). Single-use + TTL make the signed proof
// non-replayable (unlike a bearer PAT). This store is the nonce bookkeeping.

// ChallengeStore holds issued, unconsumed nonces with an expiry.
type ChallengeStore struct {
	ttl time.Duration
	mu  sync.Mutex
	n   map[string]time.Time // nonce → expiry
	now func() time.Time     // injectable clock (tests)
}

// NewChallengeStore creates a store with the given nonce TTL.
func NewChallengeStore(ttl time.Duration) *ChallengeStore {
	return &ChallengeStore{ttl: ttl, n: map[string]time.Time{}, now: time.Now}
}

// maxNonces caps outstanding nonces (review fast-follow): the unauthenticated
// /v1/challenge endpoint must not allow unbounded memory growth under a flood. When
// the cap is hit we sweep expired entries once; if still full, Issue returns "" and
// HandleChallenge answers 429 (the nonce is cheap + short-lived, so a transient
// refusal is safe — clients retry). Pair with ingress rate-limiting.
const maxNonces = 4096

// Issue returns a fresh random nonce valid for ttl, or "" if the store is at
// capacity (flood protection).
func (c *ChallengeStore) Issue() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	nonce := base64.RawURLEncoding.EncodeToString(b[:])
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.n) >= maxNonces {
		// sweep expired once, then refuse if still full.
		now := c.now()
		for k, exp := range c.n {
			if now.After(exp) {
				delete(c.n, k)
			}
		}
		if len(c.n) >= maxNonces {
			return ""
		}
	}
	c.n[nonce] = c.now().Add(c.ttl)
	return nonce
}

// Consume validates a nonce and removes it (single-use). Returns false if unknown
// or expired.
func (c *ChallengeStore) Consume(nonce string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.n[nonce]
	if !ok {
		return false
	}
	delete(c.n, nonce) // single-use regardless of expiry outcome
	return !c.now().After(exp)
}

// HandleChallenge issues a nonce (POST /v1/challenge). The response is
// {"nonce": "..."}; the caller signs the raw nonce bytes.
func (b *Broker) HandleChallenge(w http.ResponseWriter, r *http.Request) {
	if b.Challenges == nil {
		http.Error(w, "challenge auth not enabled", http.StatusNotImplemented)
		return
	}
	nonce := b.Challenges.Issue()
	if nonce == "" {
		http.Error(w, "challenge store at capacity, retry", http.StatusTooManyRequests)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"nonce": nonce})
}

// consumeNonce validates + single-use-consumes a nonce across ALL replicas. The
// ChallengeStore is per-pod, but the broker runs >1 replica behind a Service, so a
// nonce issued on replica A (via /v1/challenge) may be presented to replica B (on
// unseal). It lives on EXACTLY ONE replica (its issuer). So: try locally first; on
// a miss, ask peers to consume it. Single-use is preserved because only the issuer
// holds it (its Consume deletes it under the store mutex). Returns true iff the
// nonce was valid + unconsumed somewhere.
func (b *Broker) consumeNonce(nonce string) bool {
	if b.Challenges != nil && b.Challenges.Consume(nonce) {
		return true
	}
	return b.consumeViaPeers(nonce)
}

// consumeViaPeers asks every peer replica (headless-Service DNS) to consume the
// nonce, returning true on the FIRST peer that reports success (the issuer). Unlike
// the async recipient fan-out this is SYNCHRONOUS — auth blocks on the result — but
// it is bounded by a short per-peer timeout and the peer count (replica count).
// Forwarded requests carry the register token; a peer never re-fans (it only ever
// checks its own local store). Off (false) when peer discovery is disabled.
func (b *Broker) consumeViaPeers(nonce string) bool {
	peers := b.resolvePeers()
	if len(peers) == 0 || b.RegisterToken == "" {
		return false
	}
	body, err := json.Marshal(map[string]string{"nonce": nonce})
	if err != nil {
		return false
	}
	for _, peer := range peers {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		hr, err := http.NewRequestWithContext(ctx, http.MethodPost, peer+"/v1/challenge/consume", bytes.NewReader(body))
		if err != nil {
			cancel()
			continue
		}
		hr.Header.Set("Content-Type", "application/json")
		hr.Header.Set("X-Seald-Register-Token", b.RegisterToken)
		hr.Header.Set("X-Seald-Forwarded", "1")
		resp, err := b.client().Do(hr)
		cancel()
		if err != nil {
			b.log().Warn("nonce peer-consume: peer unreachable", "peer", peer, "err", err.Error())
			continue
		}
		ok := resp.StatusCode == http.StatusOK
		_ = resp.Body.Close()
		if ok {
			return true // the issuer consumed it (single-use holds — only it had it)
		}
	}
	return false
}

// HandleChallengeConsume is the PEER-ONLY endpoint a sibling replica calls to
// consume a nonce it doesn't hold locally (see consumeViaPeers). It consumes the
// nonce against THIS replica's local store ONLY (never re-fans → no loop), and is
// gated on the shared register token so an external caller can't burn nonces.
// 200 = consumed here; 409 = not held / already used here.
func (b *Broker) HandleChallengeConsume(w http.ResponseWriter, r *http.Request) {
	if b.Challenges == nil {
		http.Error(w, "challenge auth not enabled", http.StatusNotImplemented)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if b.RegisterToken == "" || r.Header.Get("X-Seald-Register-Token") != b.RegisterToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Nonce == "" {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if !b.Challenges.Consume(req.Nonce) {
		http.Error(w, "nonce not held here", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
