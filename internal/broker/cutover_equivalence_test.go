package broker

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"

	"github.com/dawnbreather/gitseal/internal/client"
	"github.com/dawnbreather/gitseal/internal/crypto"
)

// TestCutoverEquivalence is the SAFETY GATE for the migration: it proves
// that loading the EXPLODED per-repo v2 key directory resolves each pid to the
// IDENTICAL age identity as loading the legacy KEK-wrapped monolith bundle.json.
// Only when this holds is it safe to relocate 338 from the git keystore into the
// broker-owned out-of-band Secret and flip the mount. Mirrors the project's
// byte-equivalence discipline (prove lossless BEFORE the flip).
func TestCutoverEquivalence(t *testing.T) {
	type repo struct {
		pid      int64
		identity string
		wrapped  []byte
		kek      []byte
	}
	var repos []repo
	for _, pid := range []int64{338, 412, 1001} {
		kp, _ := crypto.GenerateRepoKey()
		kek, _ := crypto.GenerateKEK()
		wrapped, _ := crypto.WrapKey([]byte(kp.Identity), kek)
		repos = append(repos, repo{pid, kp.Identity, wrapped, kek})
	}

	dir := t.TempDir()

	// (a) LEGACY monolith bundle.json = {pid: {wrapped_key_b64, kek_b64}}.
	monolith := map[string]map[string]string{}
	for _, r := range repos {
		monolith[strconv.FormatInt(r.pid, 10)] = map[string]string{
			"wrapped_key_b64": base64.StdEncoding.EncodeToString(r.wrapped),
			"kek_b64":         base64.StdEncoding.EncodeToString(r.kek),
		}
	}
	mdata, _ := json.Marshal(monolith)
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, mdata, 0600); err != nil {
		t.Fatal(err)
	}

	// (b) EXPLODED v2 keystore dir = one raw-identity <pid>.key.json per repo (the
	// relocated form: what `admin onboard`/migration writes into the broker Secret).
	keysDir := filepath.Join(dir, "keys")
	os.MkdirAll(keysDir, 0755)
	for _, r := range repos {
		data, _ := json.Marshal(client.NewKeyFileV2(r.pid, r.identity))
		os.WriteFile(filepath.Join(keysDir, client.KeyFileName(r.pid)), data, 0600)
	}

	fromMonolith, err := LoadKeyStore(bundlePath)
	if err != nil {
		t.Fatalf("LoadKeyStore: %v", err)
	}
	fromDir, skipped, err := LoadKeyStoreDir(keysDir)
	if err != nil {
		t.Fatalf("LoadKeyStoreDir: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("no key should be skipped: %v", skipped)
	}

	if len(fromMonolith.Identities) != len(fromDir.Identities) {
		t.Fatalf("identity count differs: monolith=%d dir=%d", len(fromMonolith.Identities), len(fromDir.Identities))
	}
	pids := make([]int64, 0, len(fromMonolith.Identities))
	for pid := range fromMonolith.Identities {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	for _, pid := range pids {
		if fromMonolith.Identities[pid] != fromDir.Identities[pid] {
			t.Errorf("pid %d: identity differs monolith vs v2-dir (migration would be LOSSY)", pid)
		}
	}
	// and each resolves to the identity we minted (sanity)
	for _, r := range repos {
		if fromDir.Identities[r.pid] != r.identity {
			t.Errorf("pid %d: v2 dir identity != minted", r.pid)
		}
	}
}
