package broker

import (
	"fmt"

	"github.com/dawnbreather/gitseal/internal/client"
)

// authViaSSH verifies an SSH challenge-response and resolves it to a gitlab
// user_id (Stage D). It does NOT perform the live member/level check —
// that stays in the shared unseal path (leg D), so SSH and PAT auth converge on
// the same live-authorization gate. Steps (all fail-closed):
//
//  1. consume the nonce (single-use + TTL) → non-replayable;
//  2. the presented fingerprint must be a REGISTERED user with a registered key;
//  3. the signature must verify against that registered key over the nonce bytes.
//
// Returns the gitlab user_id on success. A caller who signs with a key that isn't
// registered, replays a nonce, or tampers the signature is denied here.
func (b *Broker) authViaSSH(fingerprint, nonce, sig string) (int64, error) {
	if b.Challenges == nil {
		return 0, fmt.Errorf("ssh auth not enabled")
	}
	// on-miss refresh: if the fingerprint isn't indexed yet (a key added to
	// a GitLab profile since the last reconcile), trigger ONE rate-limited index
	// rebuild BEFORE consuming the nonce, so a just-onboarded key resolves in
	// seconds instead of waiting a full poll interval. Done before Consume so the
	// nonce isn't burned by a first attempt that only failed on a stale index.
	if _, _, ok := b.resolveSigner(fingerprint); !ok {
		b.onMissRefresh()
	}
	// consumeNonce is replica-aware: the nonce may have been issued by a SIBLING
	// replica (the broker runs >1 behind a Service). It tries locally, then asks
	// peers — single-use holds because the nonce lives on exactly one replica.
	if !b.consumeNonce(nonce) {
		return 0, fmt.Errorf("nonce unknown, expired, or already used (no replay)")
	}
	uid, keyLine, ok := b.resolveSigner(fingerprint)
	if !ok {
		return 0, fmt.Errorf("fingerprint %s is not a known gitseal user (no GitLab profile key on a covered project)", fingerprint)
	}
	pub, err := client.ParseAuthorizedKey(keyLine)
	if err != nil {
		return 0, fmt.Errorf("resolved key for %s is unparseable: %w", fingerprint, err)
	}
	// Guard against a fingerprint/key mismatch in the source: the presented
	// fingerprint must actually be this key's fingerprint.
	if client.KeyFingerprint(pub) != fingerprint {
		return 0, fmt.Errorf("resolved key fingerprint mismatch for %s", fingerprint)
	}
	if err := client.VerifySSHSig(pub, []byte(nonce), sig); err != nil {
		return 0, fmt.Errorf("challenge signature does not verify: %w", err)
	}
	return uid, nil
}

// resolveSigner maps an ssh fingerprint → (gitlab user_id, authorized-key line),
// preferring the GitLab-built IdentityIndex and falling back to the
// legacy Registry users map (migration window). This is the single resolution
// rule shared by authViaSSH and /v1/signer/resolve. It does NOT authorize — the
// live members/all + account gate on unseal is unchanged.
func (b *Broker) resolveSigner(fingerprint string) (uid int64, keyLine string, ok bool) {
	if b.Identity != nil {
		if u, pk, found := b.Identity.Lookup(fingerprint); found {
			return u, pk, true
		}
	}
	if b.Registry != nil {
		u, uok := b.Registry.User(fingerprint)
		k, kok := b.Registry.UserKey(fingerprint)
		if uok && kok {
			return u, k, true
		}
	}
	return 0, "", false
}
