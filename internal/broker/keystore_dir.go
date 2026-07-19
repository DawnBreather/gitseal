package broker

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/dawnbreather/gitseal/internal/client"
)

// LoadKeyStoreDir loads a DIRECTORY of per-repo <pid>.key.json files into a broker
// KeyStore, TOLERANTLY: a malformed key file is skipped (and returned in `skipped`)
// instead of aborting the whole broker. This is the structural SPOF kill — one bad
// key downs only its own repo, not the fleet, replacing the monolithic bundle.json
// whose single parse error (LoadKeyStore) took every repo down. Fatal only if the
// dir is unreadable or ZERO valid keys are present (an empty keystore is a loud
// failure, never a silent-healthy one). It delegates the parse/validate to
// client.LoadKeyDir (the same code path verify-keys and admin onboard use, so the
// file format has one owner) and adapts the result into the broker's KeyStore.
func LoadKeyStoreDir(dir string) (ks *KeyStore, skipped []string, err error) {
	cks, skipped, err := client.LoadKeyDir(dir)
	if err != nil {
		return nil, skipped, err
	}
	return &KeyStore{Identities: cks.Identities}, skipped, nil
}

// HandleHealthz is a pure LIVENESS ping: 200 if the process is up, independent of
// key state. (Split from readiness so a broker that is alive-but-not-ready is not
// killed by the liveness probe.)
func (b *Broker) HandleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// HandleReadyz is a POSITIVE readiness assertion: 200 only when the broker can
// actually serve — i.e. it holds >= 1 usable key. It reports the number of loaded
// keys and the DEGRADED set (skipped/bad key files) so a silently-down repo is
// visible in the probe body (the anti-silent-health invariant: readiness is a
// positive signal, not the absence of a crash). A broker with zero keys returns
// 503 — it is alive but cannot do its job, so it should not receive traffic.
func (b *Broker) HandleReadyz(w http.ResponseWriter, r *http.Request) {
	b.keyMu.RLock()
	n := 0
	if b.Keys != nil {
		n = len(b.Keys.Identities)
	}
	degraded := append([]string(nil), b.Skipped...)
	draining := b.draining
	b.keyMu.RUnlock()

	// Draining: report NOT ready so the pod is pulled from Service endpoints while
	// in-flight unseals finish (the in-process drain — distroless has no preStop sleep).
	if draining {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("draining"))
		return
	}

	var sb strings.Builder
	if n == 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(&sb, "not ready: 0 keys loaded")
		if len(degraded) > 0 {
			fmt.Fprintf(&sb, "; degraded: %s", strings.Join(degraded, ", "))
		}
		_, _ = w.Write([]byte(sb.String()))
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(&sb, "ready: %d key(s) loaded", n)
	if len(degraded) > 0 {
		fmt.Fprintf(&sb, "; degraded (%d skipped): %s", len(degraded), strings.Join(degraded, ", "))
	}
	_, _ = w.Write([]byte(sb.String()))
}

// LoadedProjectIDs returns the sorted project ids the broker currently serves
// (for the startup log line + observability).
func (b *Broker) LoadedProjectIDs() []string {
	b.keyMu.RLock()
	defer b.keyMu.RUnlock()
	if b.Keys == nil {
		return nil
	}
	ids := make([]string, 0, len(b.Keys.Identities))
	for pid := range b.Keys.Identities {
		ids = append(ids, strconv.FormatInt(pid, 10))
	}
	sort.Strings(ids)
	return ids
}
