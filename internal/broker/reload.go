package broker

import (
	"context"
	"time"

	"filippo.io/age"
)

// The broker's keyMu (RWMutex, declared on the struct) guards live keystore swaps:
// keys are read on every unseal (RLock) and replaced by the poll-based hot-reloader
// (Lock), so many concurrent reads proceed while a swap is exclusive.

// BeginDrain marks the broker as draining so /readyz starts returning 503 (the
// pod is removed from Service endpoints) while in-flight requests finish. Called
// on SIGTERM before graceful server shutdown — the in-process equivalent of a
// preStop sleep (the distroless image has no shell/sleep binary).
func (b *Broker) BeginDrain() {
	b.keyMu.Lock()
	b.draining = true
	b.keyMu.Unlock()
}

// keyFor returns the age identity for a project id under a read lock, so it is
// safe against a concurrent hot-reload swap. This is the ONLY accessor the unseal
// path uses to read key material — it hands the identity straight to
// crypto.UnsealVerified (no KEK unwrap step).
func (b *Broker) keyFor(projectID int64) (identity string, ok bool) {
	b.keyMu.RLock()
	defer b.keyMu.RUnlock()
	if b.Keys == nil {
		return "", false
	}
	id, ok := b.Keys.Identities[projectID]
	if !ok || id == "" {
		return "", false
	}
	return id, true
}

// keyForPubkey resolves a project PUBLIC KEY (age recipient) to its private
// identity AND its numeric project_id, under a read lock (v4). A v4
// unseal request carries the pubkey instead of the numeric id; the broker needs
// the identity (to decrypt) and the numeric id (for the live members/all check).
// It scans the loaded identities computing each one's recipient — the keystore is
// small (one entry per onboarded repo) and unseal is off the pod-delivery hot
// path, so a linear scan is fine and keeps the broker registry-independent (the
// numeric id comes from the key file the identity was loaded under, never a
// registry lookup). A malformed/unknown pubkey resolves to ok=false (fail closed).
func (b *Broker) keyForPubkey(pubkey string) (identity string, projectID int64, ok bool) {
	if _, err := age.ParseX25519Recipient(pubkey); err != nil {
		return "", 0, false
	}
	b.keyMu.RLock()
	defer b.keyMu.RUnlock()
	if b.Keys == nil {
		return "", 0, false
	}
	for pid, id := range b.Keys.Identities {
		aid, err := age.ParseX25519Identity(id)
		if err != nil {
			continue // a malformed stored identity can't be this pubkey
		}
		if aid.Recipient().String() == pubkey {
			return id, pid, true
		}
	}
	return "", 0, false
}

// keyCount returns the number of live keys (read-locked).
func (b *Broker) keyCount() int {
	b.keyMu.RLock()
	defer b.keyMu.RUnlock()
	if b.Keys == nil {
		return 0
	}
	return len(b.Keys.Identities)
}

// SwapKeys atomically replaces the live keystore + degraded set, EXCEPT it refuses
// a swap to an EMPTY keystore: the never-shrink-below-last-known-good invariant. A
// reload that momentarily yields zero valid keys (a transient projected-Secret
// relink, a bad batch) must NOT blank a broker that was serving — it keeps the
// prior good keys. Returns true iff the swap was applied.
func (b *Broker) SwapKeys(ks *KeyStore, skipped []string) bool {
	if ks == nil || len(ks.Identities) == 0 {
		return false
	}
	b.keyMu.Lock()
	defer b.keyMu.Unlock()
	b.Keys = ks
	b.Skipped = skipped
	return true
}

// ReloadOnce re-reads the keystore dir and swaps in the result. A load error
// (unreadable dir, or ZERO valid keys) is a no-op that KEEPS the last-known-good —
// the broker never degrades below what it was already serving on a bad reload.
// Returns the skip list from the attempted load (nil on a kept-good no-op) + whether
// a swap happened.
func (b *Broker) ReloadOnce(dir string) (skipped []string, swapped bool) {
	ks, skipped, err := LoadKeyStoreDir(dir)
	if err != nil {
		b.log().Warn("keystore reload: kept last-known-good (load failed)", "dir", dir, "err", err.Error())
		return nil, false
	}
	if b.SwapKeys(ks, skipped) {
		for _, s := range skipped {
			b.log().Warn("keystore reload: skipped key file (degraded)", "detail", s)
		}
		return skipped, true
	}
	b.log().Warn("keystore reload: refused empty swap, kept last-known-good", "dir", dir)
	return skipped, false
}

// PollReload runs ReloadOnce every interval until ctx is cancelled. Poll-based
// (not fsnotify) on purpose: it is dependency-free and robust to Kubernetes
// projected-Secret updates, which relink the mount's symlink atomically in a way
// inotify-style watchers frequently miss. The broker is off the pod-delivery
// critical path, so a bounded poll lag (onboarding is rare) is an acceptable
// trade for the simpler, more reliable mechanism.
func (b *Broker) PollReload(ctx context.Context, dir string, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.ReloadOnce(dir)
		}
	}
}
