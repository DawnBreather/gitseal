package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// --- dynamic recipient registry --------------------------------------
//
// The recipient a bundle's env section is sealed to is no longer static git config
// — it is registered DYNAMICALLY by the per-cluster gitseal-controller, which mints
// the materializer keypair locally and POSTs its PUBLIC recipient here. This is
// SOFT STATE (like the IdentityIndex): not persisted; controllers re-register
// every reconcile, so a broker restart repopulates within a poll. The snapshot
// OVERLAYS these onto the static projects.json recipients so `seal` targets the
// dynamically-onboarded env.

// regKey identifies a (project, env) recipient registration.
type regKey struct {
	Project string
	Env     string
}

// RecipientEntry is a registered materializer recipient + the env's delivery config
// (carried so a fully-dynamic env, absent from static projects.json, still resolves
// namespace/min_level in the snapshot).
type RecipientEntry struct {
	Recipient string
	Cluster   string
	Namespace string
	MinLevel  int
}

// RecipientRegistry is the concurrent-safe (project,env)→RecipientEntry soft state.
type RecipientRegistry struct {
	mu sync.RWMutex
	m  map[regKey]RecipientEntry
}

func NewRecipientRegistry() *RecipientRegistry {
	return &RecipientRegistry{m: map[regKey]RecipientEntry{}}
}

func (rr *RecipientRegistry) set(project, env string, e RecipientEntry) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	rr.m[regKey{project, env}] = e
}

// forProject returns the registered env→RecipientEntry for a project (read-locked).
func (rr *RecipientRegistry) forProject(project string) map[string]RecipientEntry {
	rr.mu.RLock()
	defer rr.mu.RUnlock()
	out := map[string]RecipientEntry{}
	for k, v := range rr.m {
		if k.Project == project {
			out[k.Env] = v
		}
	}
	return out
}

type registerRequest struct {
	ProjectRecipient string `json:"project_recipient"`
	Env              string `json:"env"`
	Recipient        string `json:"recipient"`
	Cluster          string `json:"cluster"`
	Namespace        string `json:"namespace"`
	MinLevel         int    `json:"min_level"`
}

// HandleRecipientRegister is the AUTHENTICATED endpoint the gitseal-controller POSTs
// a freshly-minted materializer recipient to. SECURITY-CRITICAL: a rogue
// recipient here would make `seal` ALSO encrypt this project/env's secrets to an
// attacker's key → the attacker could decrypt them. So it requires the shared
// registration token (X-Seald-Register-Token); disabled (503) without one.
func (b *Broker) HandleRecipientRegister(w http.ResponseWriter, r *http.Request) {
	if b.RegisterToken == "" {
		http.Error(w, "recipient registration not enabled", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Seald-Register-Token") != b.RegisterToken {
		b.log().Warn("recipient register: rejected (bad/missing token)")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.ProjectRecipient == "" || req.Env == "" || req.Recipient == "" {
		http.Error(w, "project_recipient, env, recipient are required", http.StatusBadRequest)
		return
	}
	if b.Recipients == nil {
		b.Recipients = NewRecipientRegistry()
	}
	b.Recipients.set(req.ProjectRecipient, req.Env, RecipientEntry{
		Recipient: req.Recipient, Cluster: req.Cluster, Namespace: req.Namespace, MinLevel: req.MinLevel,
	})
	b.log().Info("recipient registered", "project", req.ProjectRecipient, "env", req.Env, "cluster", req.Cluster)

	// Peer fan-out: a controller POSTs to ONE replica (via the Service),
	// but the registry is per-pod. Forward this registration to the other replicas
	// so EVERY replica's snapshot is coherent — otherwise seal round-robins into a
	// split brain. Only fan out an ORIGINAL (client) registration, never a forwarded
	// one (X-Seald-Forwarded), to break the loop. Best-effort + async: the local
	// set already succeeded (200 to the controller); a peer that misses gets the
	// value on the controller's next reconcile.
	if r.Header.Get("X-Seald-Forwarded") == "" {
		b.fanOutRegistration(req)
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// fanOutRegistration forwards a registration to every peer replica (best-effort).
// Peers are discovered by resolving the headless-Service DNS to all pod IPs and
// excluding this pod's own IP. Marked X-Seald-Forwarded so a peer does not re-fan.
func (b *Broker) fanOutRegistration(req registerRequest) {
	peers := b.resolvePeers()
	if len(peers) == 0 {
		return
	}
	body, err := json.Marshal(req)
	if err != nil {
		return
	}
	for _, peer := range peers {
		go func(url string) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			hr, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/v1/recipient/register", bytes.NewReader(body))
			if err != nil {
				return
			}
			hr.Header.Set("Content-Type", "application/json")
			hr.Header.Set("X-Seald-Register-Token", b.RegisterToken)
			hr.Header.Set("X-Seald-Forwarded", "1")
			resp, err := b.client().Do(hr)
			if err != nil {
				b.log().Warn("recipient fan-out: peer unreachable", "peer", url, "err", err.Error())
				return
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				b.log().Warn("recipient fan-out: peer rejected", "peer", url, "code", resp.StatusCode)
			}
		}(peer)
	}
}

// resolvePeers returns the base URLs (http://ip:port) of the OTHER broker replicas,
// discovered via the headless Service DNS. Off (empty) when PeerDNS is unset. The
// peerURLs test seam overrides discovery. Self (SelfIP) is excluded.
func (b *Broker) resolvePeers() []string {
	if b.peerURLs != nil {
		return b.peerURLs()
	}
	if b.PeerDNS == "" {
		return nil
	}
	ips, err := net.LookupHost(b.PeerDNS)
	if err != nil {
		b.log().Warn("recipient fan-out: peer DNS lookup failed", "dns", b.PeerDNS, "err", err.Error())
		return nil
	}
	port := b.PeerPort
	if port == "" {
		port = "8080"
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip == b.SelfIP {
			continue // don't forward to ourselves
		}
		out = append(out, fmt.Sprintf("http://%s", net.JoinHostPort(ip, port)))
	}
	return out
}
