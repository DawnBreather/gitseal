package broker

import (
	"encoding/json"
	"net/http"
)

// --- broker-hosted registry (Stage C) --------------------------------
//
// The broker is the single AUTHORITY for two maps (seeded out-of-band, like the
// keystore — never git):
//   - Projects: project pubkey → its PUBLIC operational config (project_id,
//     env→cluster, env_min_level, cluster recipients). This is what a repo's
//     .seald/repo.yaml used to duplicate; centralizing it kills the drift.
//   - Users: ssh fingerprint → gitlab user_id (populated at user onboarding).
//
// The projects map is distributed JWKS-style as a cached snapshot; the users map
// is broker-internal (used to resolve a signer/caller) and is NEVER in the snapshot.

// ProjectEntry is one project's public operational config.
// ProjectEnv is one environment's public config: env owns its age
// recipient (crypto boundary is the env, so prod≠preprod even on one cluster) +
// its delivery namespace.
type ProjectEnv struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	MinLevel  int    `json:"min_level"`
	Recipient string `json:"recipient"`
}

type ProjectEntry struct {
	ProjectID int64                 `json:"project_id"`
	Envs      map[string]ProjectEnv `json:"envs,omitempty"`

	// legacy — read-only back-compat; omitted on write.
	EnvCluster        map[string]string `json:"env_cluster,omitempty"`
	EnvMinLevel       map[string]int    `json:"env_min_level,omitempty"`
	ClusterRecipients map[string]string `json:"cluster_recipients,omitempty"`
}

// UnmarshalJSON derives Envs from a legacy-shape entry when `envs` is absent, so a
// mid-migration projects.json still resolves (a legacy env's recipient is its
// cluster's shared key). Legacy maps are then cleared so the snapshot serializes
// only the new shape.
func (e *ProjectEntry) UnmarshalJSON(data []byte) error {
	type raw ProjectEntry
	var r raw
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	*e = ProjectEntry(r)
	if e.Envs == nil && len(e.EnvCluster) > 0 {
		e.Envs = map[string]ProjectEnv{}
		for env, cluster := range e.EnvCluster {
			e.Envs[env] = ProjectEnv{
				Cluster:   cluster,
				Recipient: e.ClusterRecipients[cluster],
				MinLevel:  e.EnvMinLevel[env],
			}
		}
	}
	e.EnvCluster, e.EnvMinLevel, e.ClusterRecipients = nil, nil, nil
	return nil
}

// Registry is the broker's authoritative state.
type Registry struct {
	Projects map[string]ProjectEntry // project pubkey → config
	Users    map[string]int64        // ssh fingerprint → gitlab user_id
	UserKeys map[string]string       // ssh fingerprint → authorized-key line (to verify signatures)
}

// UserKey resolves a fingerprint to its registered SSH public key line.
func (r *Registry) UserKey(fingerprint string) (string, bool) {
	if r == nil {
		return "", false
	}
	k, ok := r.UserKeys[fingerprint]
	return k, ok
}

// Project resolves a project pubkey to its config.
func (r *Registry) Project(pubkey string) (ProjectEntry, bool) {
	if r == nil {
		return ProjectEntry{}, false
	}
	e, ok := r.Projects[pubkey]
	return e, ok
}

// User resolves an ssh fingerprint to a gitlab user_id.
func (r *Registry) User(fingerprint string) (int64, bool) {
	if r == nil {
		return 0, false
	}
	uid, ok := r.Users[fingerprint]
	return uid, ok
}

// RegistrySnapshot is the PUBLIC, cacheable view consumers pull (seal/verify). It
// contains ONLY project config — no private keys, no user registry.
type RegistrySnapshot struct {
	Projects map[string]ProjectEntry `json:"projects"`
}

// HandleRegistrySnapshot serves the public project snapshot (JWKS-style). It NEVER
// includes the user registry or any private material. Cacheable by clients.
func (b *Broker) HandleRegistrySnapshot(w http.ResponseWriter, r *http.Request) {
	snap := RegistrySnapshot{Projects: map[string]ProjectEntry{}}
	if b.Registry != nil {
		for k, v := range b.Registry.Projects {
			snap.Projects[k] = v
		}
	}
	// OVERLAY the dynamically-registered recipients onto the static config.
	// A controller-registered recipient WINS over the static projects.json one (the
	// dynamic key is the live truth), and a fully-dynamic env (absent from static
	// config) is added, carrying its own namespace/min_level.
	if b.Recipients != nil {
		for pub := range collectProjects(snap.Projects, b.Recipients) {
			entry := snap.Projects[pub] // zero value if only dynamic
			if entry.Envs == nil {
				entry.Envs = map[string]ProjectEnv{}
			} else {
				entry.Envs = cloneEnvs(entry.Envs) // don't mutate the shared Registry map
			}
			for env, re := range b.Recipients.forProject(pub) {
				cur := entry.Envs[env] // preserve static namespace/min_level when present
				cur.Recipient = re.Recipient
				if re.Cluster != "" {
					cur.Cluster = re.Cluster
				}
				if re.Namespace != "" {
					cur.Namespace = re.Namespace
				}
				if re.MinLevel != 0 {
					cur.MinLevel = re.MinLevel
				}
				entry.Envs[env] = cur
			}
			snap.Projects[pub] = entry
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300") // JWKS-style short cache
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(snap)
}

// collectProjects returns the union of project pubkeys across the static snapshot
// and the dynamic recipient registry (so fully-dynamic projects are included).
func collectProjects(static map[string]ProjectEntry, rr *RecipientRegistry) map[string]struct{} {
	out := map[string]struct{}{}
	for k := range static {
		out[k] = struct{}{}
	}
	rr.mu.RLock()
	for k := range rr.m {
		out[k.Project] = struct{}{}
	}
	rr.mu.RUnlock()
	return out
}

func cloneEnvs(in map[string]ProjectEnv) map[string]ProjectEnv {
	out := make(map[string]ProjectEnv, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
