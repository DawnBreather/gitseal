package broker

import (
	"errors"
	"sync"

	"github.com/dawnbreather/gitseal/internal/client"
)

// ErrProjectNotVisible marks a project the broker's service token cannot see
// (GitLab 404/403 — it isn't a member). Unlike a transient network/5xx error,
// this is PERMANENT for that (token, project) pair, so buildIndex SKIPS such a
// project instead of aborting: onboarding a project the broker isn't a member of
// must never blank the index and lock out every developer on the OTHER projects.
var ErrProjectNotVisible = errors.New("project not visible to service token")

// --- broker identity index -------------------------------------------
//
// The broker BUILDS fp → (uid, pubkey) itself from GitLab (project members →
// their profile SSH keys), replacing the hand-maintained users.json/userkeys.json.
// This makes SSH-key onboarding IMPLICIT: a developer with a key on their GitLab
// profile who is a project member is resolvable, with no `admin onboard-user`.
//
// The index only RESOLVES identity; per-unseal authorization stays the LIVE
// members/all + account check (unchanged). A stale/missing fp → fail-closed.

// IndexEntry is a resolved signer: their GitLab user id + the authorized-key line
// (to verify a challenge/section signature).
type IndexEntry struct {
	UserID int64
	PubKey string // authorized-key line ("ssh-ed25519 AAAA… comment")
}

// IdentityIndex is the atomic, concurrent-safe fp→IndexEntry map (read on every
// SSH unseal, replaced by the reconcile loop) — same swap discipline as KeyStore.
type IdentityIndex struct {
	mu sync.RWMutex
	m  map[string]IndexEntry
}

func NewIdentityIndex() *IdentityIndex {
	return &IdentityIndex{m: map[string]IndexEntry{}}
}

// Lookup resolves a fingerprint (read-locked).
func (ix *IdentityIndex) Lookup(fp string) (uid int64, pubkey string, ok bool) {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	e, ok := ix.m[fp]
	return e.UserID, e.PubKey, ok
}

// Swap atomically replaces the map, EXCEPT it refuses an EMPTY swap so a transient
// reconcile that yields nothing (GitLab blip) never blanks a working index —
// last-known-good, mirroring KeyStore.SwapKeys. Returns true iff applied.
func (ix *IdentityIndex) Swap(m map[string]IndexEntry) bool {
	if len(m) == 0 {
		return false
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ix.m = m
	return true
}

// Count returns the number of indexed fingerprints (read-locked).
func (ix *IdentityIndex) Count() int {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return len(ix.m)
}

// indexFetcher abstracts the two forward GitLab reads reconcile needs, so the
// assembly logic is testable without HTTP.
type indexFetcher struct {
	members func(projectID int64) ([]int64, error) // project member user ids
	keys    func(userID int64) ([]string, error)   // a user's authorized-key lines
}

// buildIndex assembles fp→IndexEntry by, for each project, listing its members and
// fetching each member's profile keys. A user in multiple projects is fetched once
// (deduped). An UNPARSEABLE key is skipped (a bad key on one profile must not sink
// the whole index). A fetch error ABORTS (return err) so the caller keeps
// last-known-good rather than swapping in a partial index that would deny a valid
// user (fail-closed = deny, but a WRONGLY-dropped user is a self-inflicted outage).
func buildIndex(projectIDs []int64, f indexFetcher) (map[string]IndexEntry, error) {
	out := map[string]IndexEntry{}
	seenUser := map[int64]bool{}
	for _, pid := range projectIDs {
		uids, err := f.members(pid)
		if err != nil {
			// A project the token can't see (404/403) is permanent → skip it so the
			// reachable projects still index. Any other (transient) error aborts, so
			// the caller keeps last-known-good rather than a partial index.
			if errors.Is(err, ErrProjectNotVisible) {
				continue
			}
			return nil, err
		}
		for _, uid := range uids {
			if seenUser[uid] {
				continue
			}
			seenUser[uid] = true
			lines, err := f.keys(uid)
			if err != nil {
				return nil, err
			}
			for _, line := range lines {
				fp, ferr := client.FingerprintOfLine(line)
				if ferr != nil {
					continue // skip an unparseable key, keep the rest
				}
				out[fp] = IndexEntry{UserID: uid, PubKey: line}
			}
		}
	}
	return out, nil
}
