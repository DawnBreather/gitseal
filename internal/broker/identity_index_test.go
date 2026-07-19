package broker

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
)

// keyLine generates a fresh ssh key and returns (authorized-key line, fingerprint).
func keyLine(t *testing.T) (string, string) {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	line := string(ssh.MarshalAuthorizedKey(sp))
	return line[:len(line)-1], ssh.FingerprintSHA256(sp)
}

// IdentityIndex maps ssh fingerprint → (uid, pubkey), built by the broker from
// GitLab instead of a hand-maintained users.json. This tests the pure
// index (Set/Lookup + atomic swap); the reconcile wiring (GitLab fetch) is tested
// separately against a stub.
func TestIdentityIndex_LookupAndSwap(t *testing.T) {
	line55, fp55 := keyLine(t)
	line87, fp87 := keyLine(t)

	idx := NewIdentityIndex()
	idx.Swap(map[string]IndexEntry{
		fp55: {UserID: 55, PubKey: line55},
		fp87: {UserID: 87, PubKey: line87},
	})

	if uid, pk, ok := idx.Lookup(fp55); !ok || uid != 55 || pk != line55 {
		t.Fatalf("fp55 lookup wrong: %d %q %v", uid, pk, ok)
	}
	if _, _, ok := idx.Lookup("SHA256:nope"); ok {
		t.Fatal("unknown fp must not resolve")
	}

	// swap is atomic + last-known-good: an EMPTY swap is refused (never blank a
	// working index — mirrors the keystore SwapKeys invariant).
	if idx.Swap(map[string]IndexEntry{}) {
		t.Fatal("empty swap must be refused")
	}
	if _, _, ok := idx.Lookup(fp87); !ok {
		t.Fatal("index blanked by an empty swap (must keep last-known-good)")
	}

	// a non-empty swap replaces.
	lineNew, fpNew := keyLine(t)
	if !idx.Swap(map[string]IndexEntry{fpNew: {UserID: 99, PubKey: lineNew}}) {
		t.Fatal("non-empty swap must apply")
	}
	if _, _, ok := idx.Lookup(fp55); ok {
		t.Fatal("old entries must be gone after a full swap")
	}
	if uid, _, ok := idx.Lookup(fpNew); !ok || uid != 99 {
		t.Fatalf("new entry missing after swap")
	}
}

// buildIndexFromGitLab is the reconcile core: given the set of project ids to
// cover and a fetcher (members-of-project, keys-of-user), it assembles the
// fp→(uid,pubkey) map. A user in MULTIPLE covered projects appears once. A key
// that fails to parse is skipped (not fatal). Tested with an in-memory fetcher so
// no HTTP is needed.
func TestBuildIndexFromGitLab(t *testing.T) {
	line55, fp55 := keyLine(t)
	line87a, fp87a := keyLine(t)
	line87b, fp87b := keyLine(t)

	members := map[int64][]int64{
		338: {55, 87},
		412: {87}, // 87 is in both — must dedupe to one identity, both keys indexed
	}
	keys := map[int64][]string{
		55: {line55},
		87: {line87a, line87b},
	}
	fetch := indexFetcher{
		members: func(pid int64) ([]int64, error) { return members[pid], nil },
		keys:    func(uid int64) ([]string, error) { return keys[uid], nil },
	}

	m, err := buildIndex([]int64{338, 412}, fetch)
	if err != nil {
		t.Fatalf("buildIndex: %v", err)
	}
	if e, ok := m[fp55]; !ok || e.UserID != 55 {
		t.Fatalf("fp55 missing")
	}
	// both of 87's keys resolve to uid 87
	for _, fp := range []string{fp87a, fp87b} {
		if e, ok := m[fp]; !ok || e.UserID != 87 {
			t.Fatalf("fp %s → uid 87 missing", fp)
		}
	}
	if len(m) != 3 {
		t.Fatalf("expected 3 fingerprints, got %d", len(m))
	}
}

// A TRANSIENT members-fetch error for one project aborts the WHOLE reconcile
// (return err → the caller keeps last-known-good, never a partial index that could
// drop a valid user and deny them).
func TestBuildIndex_FetchErrorAborts(t *testing.T) {
	fetch := indexFetcher{
		members: func(pid int64) ([]int64, error) { return nil, errBoom },
		keys:    func(uid int64) ([]string, error) { return nil, nil },
	}
	if _, err := buildIndex([]int64{338}, fetch); err == nil {
		t.Fatal("a members-fetch error must abort reconcile (keep last-known-good)")
	}
}

// A project the service token CANNOT SEE (404/403 → ErrProjectNotVisible) is a
// PERMANENT condition, not a transient blip: skipping it must NOT sink the whole
// index. Otherwise onboarding one project the broker's token isn't a member of
// (e.g. a freshly-added tenant) locks out EVERY developer fleet-wide. So buildIndex
// SKIPS an unseeable project and still indexes the reachable ones.
func TestBuildIndex_ProjectNotVisibleSkipped(t *testing.T) {
	line55, fp55 := keyLine(t)
	members := map[int64][]int64{338: {55}}
	keys := map[int64][]string{55: {line55}}
	fetch := indexFetcher{
		members: func(pid int64) ([]int64, error) {
			if pid == 359 {
				return nil, ErrProjectNotVisible // token isn't a member of 359
			}
			return members[pid], nil
		},
		keys: func(uid int64) ([]string, error) { return keys[uid], nil },
	}
	m, err := buildIndex([]int64{338, 359}, fetch)
	if err != nil {
		t.Fatalf("an unseeable project must be skipped, not fatal: %v", err)
	}
	if e, ok := m[fp55]; !ok || e.UserID != 55 {
		t.Fatalf("reachable project 338 must still be indexed; got %v", m)
	}
	if len(m) != 1 {
		t.Fatalf("expected 1 fingerprint (338 only), got %d", len(m))
	}
}

var errBoom = &boomErr{}

type boomErr struct{}

func (*boomErr) Error() string { return "boom" }
