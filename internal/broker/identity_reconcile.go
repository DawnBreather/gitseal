package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// gitLabFetcher builds an indexFetcher backed by the broker's authenticated
// gitlabGET + service token (the non-admin read_api token). Forward calls only:
//
//	members: GET /projects/:id/members/all?per_page=100  → member user ids
//	keys:    GET /users/:id/keys                          → authorized-key lines
//
// Both work with a non-admin token (verified live) — no admin/reverse-lookup.
func (b *Broker) gitLabFetcher(ctx context.Context) indexFetcher {
	return indexFetcher{
		members: func(pid int64) ([]int64, error) {
			// per_page=100 covers current projects; pagination is a follow-up if a
			// project ever exceeds it (a member beyond page 1 would be missed → they'd
			// fail-closed, not bypass, and the on-miss refresh doesn't help there —
			// noted as a known bound).
			path := fmt.Sprintf("/api/v4/projects/%d/members/all?per_page=100", pid)
			code, body, err := b.gitlabGET(ctx, path, b.ServiceToken)
			if err != nil {
				return nil, err
			}
			// 404/403 = the service token isn't a member of this project → permanent,
			// skip it (ErrProjectNotVisible) rather than sinking the whole index. Any
			// other non-200 is treated as transient (abort → keep last-known-good).
			if code == 404 || code == 403 {
				return nil, fmt.Errorf("members/all(%d) returned %d: %w", pid, code, ErrProjectNotVisible)
			}
			if code != 200 {
				return nil, fmt.Errorf("members/all(%d) returned %d", pid, code)
			}
			var ms []struct {
				ID int64 `json:"id"`
			}
			if err := json.Unmarshal(body, &ms); err != nil {
				return nil, fmt.Errorf("parse members(%d): %w", pid, err)
			}
			ids := make([]int64, 0, len(ms))
			for _, m := range ms {
				ids = append(ids, m.ID)
			}
			return ids, nil
		},
		keys: func(uid int64) ([]string, error) {
			code, body, err := b.gitlabGET(ctx, fmt.Sprintf("/api/v4/users/%d/keys", uid), b.ServiceToken)
			if err != nil {
				return nil, err
			}
			if code != 200 {
				return nil, fmt.Errorf("users/%d/keys returned %d", uid, code)
			}
			var ks []struct {
				Key string `json:"key"`
			}
			if err := json.Unmarshal(body, &ks); err != nil {
				return nil, fmt.Errorf("parse keys(%d): %w", uid, err)
			}
			lines := make([]string, 0, len(ks))
			for _, k := range ks {
				if k.Key != "" {
					lines = append(lines, k.Key)
				}
			}
			return lines, nil
		},
	}
}

// coveredProjectIDs is the set the index reconciles: exactly the projects whose
// keys the broker holds (Keys.Identities) — the only projects it can unseal for,
// so the only ones whose members need resolving. Read-locked.
func (b *Broker) coveredProjectIDs() []int64 {
	b.keyMu.RLock()
	defer b.keyMu.RUnlock()
	if b.Keys == nil {
		return nil
	}
	ids := make([]int64, 0, len(b.Keys.Identities))
	for pid := range b.Keys.Identities {
		ids = append(ids, pid)
	}
	return ids
}

// ReconcileIdentityIndex rebuilds the index from GitLab and swaps it in. A build
// error is a no-op that KEEPS the last-known-good (like the keystore reload) — a
// GitLab blip must never blank the index and lock every developer out. Returns
// (count, swapped, err).
func (b *Broker) ReconcileIdentityIndex(ctx context.Context) (int, bool, error) {
	if b.Identity == nil || b.ServiceToken == "" {
		return 0, false, nil // index disabled (no service token) — PAT path unaffected
	}
	pids := b.coveredProjectIDs()
	if len(pids) == 0 {
		return 0, false, nil
	}
	m, err := buildIndex(pids, b.gitLabFetcher(ctx))
	if err != nil {
		b.log().Warn("identity index: kept last-known-good (reconcile failed)", "err", err.Error())
		return b.Identity.Count(), false, err
	}
	swapped := b.Identity.Swap(m)
	if !swapped {
		b.log().Warn("identity index: refused empty swap, kept last-known-good")
	}
	return len(m), swapped, nil
}

// PollIdentityIndex reconciles the index every interval until ctx is cancelled —
// the source-of-truth loop (system hooks, if configured, are a latency layer on
// top). Poll-based for the same reason as the keystore reload: robust + simple.
func (b *Broker) PollIdentityIndex(ctx context.Context, interval time.Duration) {
	// prime immediately so the broker is useful without waiting a full interval.
	_, _, _ = b.ReconcileIdentityIndex(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _, _ = b.ReconcileIdentityIndex(ctx)
		}
	}
}

// onMissRefresh reconciles the index on an unseal whose fingerprint isn't indexed
// yet (a key just added to a GitLab profile), dropping onboarding latency from the
// poll interval to seconds. RATE-LIMITED (min interval between on-miss reconciles)
// so a flood of bogus fingerprints can't hammer GitLab — a DoS-via-unknown-fp guard.
// Best-effort + non-blocking on the rate limit: if throttled, the caller just uses
// the current index (fail-closed if still absent), and the next poll catches up.
func (b *Broker) onMissRefresh() {
	if b.Identity == nil || b.ServiceToken == "" {
		return
	}
	b.missMu.Lock()
	now := time.Now()
	if !b.lastMiss.IsZero() && now.Sub(b.lastMiss) < onMissMinInterval {
		b.missMu.Unlock()
		return // throttled
	}
	b.lastMiss = now
	b.missMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), unsealDeadline)
	defer cancel()
	_, _, _ = b.ReconcileIdentityIndex(ctx)
}

// onMissMinInterval throttles on-miss reconciles (a full members×keys sweep) so a
// burst of unknown fingerprints can't turn each into a GitLab fan-out.
const onMissMinInterval = 10 * time.Second
