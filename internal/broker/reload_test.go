package broker

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

// --- Stage 3: keystore hot-reload (poll-based, last-known-good) ----------------

// SwapKeys atomically replaces the live keystore + skipped set behind the broker's
// RWMutex, EXCEPT it refuses a swap to an empty keystore — the never-shrink-below-
// last-known-good invariant: a reload that yields zero valid keys (e.g. a transient
// empty projected-Secret relink) keeps the prior good keys rather than blanking the
// broker. Returns whether the swap was applied.
func TestSwapKeys_LastKnownGood(t *testing.T) {
	b := &Broker{}
	good := &KeyStore{Identities: map[int64]string{338: "id-338"}}
	if !b.SwapKeys(good, nil) {
		t.Fatal("first swap to a non-empty keystore must apply")
	}
	if b.keyCount() != 1 {
		t.Fatalf("expected 1 key after swap, got %d", b.keyCount())
	}
	// a swap to an EMPTY keystore must be REFUSED (keep last-known-good)
	if b.SwapKeys(&KeyStore{Identities: map[int64]string{}}, []string{"338.key.json: boom"}) {
		t.Fatal("swap to an empty keystore must be refused")
	}
	if b.keyCount() != 1 {
		t.Fatalf("keystore must retain last-known-good after a refused empty swap, got %d", b.keyCount())
	}
	// a swap to a different non-empty keystore applies
	next := &KeyStore{Identities: map[int64]string{412: "id-412"}}
	if !b.SwapKeys(next, nil) {
		t.Fatal("swap to a non-empty keystore must apply")
	}
	if _, ok := b.keyFor(412); !ok {
		t.Fatal("new key 412 must be live after swap")
	}
	if _, ok := b.keyFor(338); ok {
		t.Fatal("old key 338 must be gone after a full swap")
	}
}

// keyFor + SwapKeys must be race-free under concurrent access (run with -race).
func TestKeyFor_ConcurrentWithSwap(t *testing.T) {
	b := &Broker{}
	b.SwapKeys(&KeyStore{Identities: map[int64]string{1: "id-1"}}, nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_, _ = b.keyFor(1)
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				b.SwapKeys(&KeyStore{Identities: map[int64]string{1: "id-" + strconv.Itoa(n)}}, nil)
			}
		}(i)
	}
	wg.Wait()
}

// ReloadOnce reads the dir and swaps; a dir that now has a bad file keeps the good
// keys (skipped reported), and a fully-unreadable/empty dir keeps last-known-good.
func TestReloadOnce_KeepsGoodOnDegradedDir(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, 338)
	writeKey(t, dir, 412)
	b := &Broker{}
	ks, skipped, err := LoadKeyStoreDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	b.SwapKeys(ks, skipped)
	if b.keyCount() != 2 {
		t.Fatalf("expected 2 keys, got %d", b.keyCount())
	}

	// corrupt one key file, then reload: the good one stays, the bad one is skipped.
	os.WriteFile(filepath.Join(dir, "412.key.json"), []byte("{bad"), 0600)
	b.ReloadOnce(dir)
	if _, ok := b.keyFor(338); !ok {
		t.Fatal("good key 338 must survive a reload with a sibling gone bad")
	}
	if _, ok := b.keyFor(412); ok {
		t.Fatal("corrupted key 412 must be dropped on reload")
	}

	// now corrupt BOTH → LoadKeyStoreDir errors (zero valid) → reload must be a
	// no-op that KEEPS the last-known-good (338 stays).
	os.WriteFile(filepath.Join(dir, "338.key.json"), []byte("{bad"), 0600)
	b.ReloadOnce(dir)
	if _, ok := b.keyFor(338); !ok {
		t.Fatal("a reload that yields zero valid keys must keep last-known-good (338)")
	}
}
