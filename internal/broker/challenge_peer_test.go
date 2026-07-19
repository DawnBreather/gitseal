package broker

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- nonce peer-consume fan-out --------------------------------------------------
//
// The ChallengeStore is per-pod in-memory soft state, but the broker runs >1
// replica behind a Service: /v1/challenge (Issue) lands on replica A while the
// unseal (Consume) round-robins to replica B → "nonce unknown" and human unseal
// fails ~50% of the time. Same split-brain class as the recipient registry
//. Unlike that async fan-out, a nonce consume must be SYNCHRONOUS (auth
// depends on the result) and single-use must hold: the nonce lives on EXACTLY ONE
// replica (its issuer), so on a local miss we ask peers to consume it; whichever
// replica holds it deletes it (under its own mutex) and reports success.

// A nonce issued on replica A is consumable on replica B via the peer-consume
// endpoint, and only ONCE (a second attempt — local or peer — fails).
func TestNonceConsumeViaPeer(t *testing.T) {
	// replica A: holds the nonce.
	replicaA := &Broker{
		Challenges:    NewChallengeStore(time.Minute),
		RegisterToken: "reg-secret",
	}
	nonce := replicaA.Challenges.Issue()
	peer := httptest.NewServer(http.HandlerFunc(replicaA.HandleChallengeConsume))
	defer peer.Close()

	// replica B: does NOT hold the nonce; peers point at A.
	replicaB := &Broker{
		Challenges:    NewChallengeStore(time.Minute),
		RegisterToken: "reg-secret",
		peerURLs:      func() []string { return []string{peer.URL} },
	}

	// B's local store misses, so it must consume via the peer (A).
	if replicaB.Challenges.Consume(nonce) {
		t.Fatal("precondition: B must not hold the nonce locally")
	}
	if !replicaB.consumeNonce(nonce) {
		t.Fatal("B must consume the nonce via peer A")
	}
	// single-use: a second consume (peer already deleted it on A) must fail.
	if replicaB.consumeNonce(nonce) {
		t.Fatal("second consume of the same nonce must fail (no replay across replicas)")
	}
}

// The peer-consume endpoint requires the register token (a rogue caller must not be
// able to burn nonces).
func TestHandleChallengeConsume_AuthRequired(t *testing.T) {
	b := &Broker{Challenges: NewChallengeStore(time.Minute), RegisterToken: "reg-secret"}
	n := b.Challenges.Issue()

	// no token → 401, nonce NOT consumed.
	r := httptest.NewRequest("POST", "/v1/challenge/consume", strings.NewReader(`{"nonce":"`+n+`"}`))
	w := httptest.NewRecorder()
	b.HandleChallengeConsume(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without token, got %d", w.Code)
	}
	if !b.Challenges.Consume(n) {
		t.Fatal("an unauthorized consume attempt must not have burned the nonce")
	}
}

// A local hit short-circuits: consumeNonce must NOT call peers when the nonce is
// held locally (avoids a needless round-trip AND a double-consume).
func TestConsumeNonce_LocalHitSkipsPeers(t *testing.T) {
	called := false
	b := &Broker{
		Challenges: NewChallengeStore(time.Minute),
		peerURLs:   func() []string { called = true; return nil },
	}
	n := b.Challenges.Issue()
	if !b.consumeNonce(n) {
		t.Fatal("local consume must succeed")
	}
	if called {
		t.Fatal("a local hit must not consult peers")
	}
}
