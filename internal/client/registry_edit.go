package client

import (
	"encoding/json"
	"fmt"
)

// RegistryEnv is one environment's config: an environment is a
// first-class {cluster, namespace, min_level, recipient}. The recipient is the
// env's OWN age public key — the crypto boundary is the ENV, so prod and preprod
// on the same cluster have DIFFERENT recipients (a prod section can't be decrypted
// by the preprod key). cluster is informational (which physical cluster / pool);
// namespace is the delivery target; min_level is the write-authz policy.
type RegistryEnv struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	MinLevel  int    `json:"min_level"`
	Recipient string `json:"recipient"`
}

// RegistryProjectEntry is one project's PUBLIC operational config in the broker
// registry projects.json. environments are first-class (Envs). The legacy
// maps (env_cluster/env_min_level/cluster_recipients) are still PARSED for
// back-compat (UnmarshalJSON derives Envs from them) but no longer WRITTEN.
type RegistryProjectEntry struct {
	ProjectID int64                  `json:"project_id"`
	Envs      map[string]RegistryEnv `json:"envs,omitempty"`

	// legacy — read-only back-compat; omitted on write.
	EnvCluster        map[string]string `json:"env_cluster,omitempty"`
	EnvMinLevel       map[string]int    `json:"env_min_level,omitempty"`
	ClusterRecipients map[string]string `json:"cluster_recipients,omitempty"`
}

// UnmarshalJSON derives the Envs model from a legacy-shape entry (env_cluster +
// env_min_level + cluster_recipients) when `envs` is absent, so a mid-migration
// projects.json still resolves. A legacy env's recipient is its cluster's shared
// recipient (the pre- behavior) until re-sealed; namespace is unknown
// (empty) in the legacy shape. The legacy maps are then cleared so the entry
// serializes in the new shape only.
func (e *RegistryProjectEntry) UnmarshalJSON(data []byte) error {
	type raw RegistryProjectEntry // avoid recursion
	var r raw
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	*e = RegistryProjectEntry(r)
	if e.Envs == nil && len(e.EnvCluster) > 0 {
		e.Envs = map[string]RegistryEnv{}
		for env, cluster := range e.EnvCluster {
			e.Envs[env] = RegistryEnv{
				Cluster:   cluster,
				Recipient: e.ClusterRecipients[cluster], // shared cluster key (legacy)
				MinLevel:  e.EnvMinLevel[env],
			}
		}
	}
	// drop legacy maps so we WRITE only the new shape.
	e.EnvCluster, e.EnvMinLevel, e.ClusterRecipients = nil, nil, nil
	return nil
}

// EnvRecipient resolves the age recipient an env's secrets are sealed to.
func (e RegistryProjectEntry) EnvRecipient(env string) (string, bool) {
	v, ok := e.Envs[env]
	if !ok || v.Recipient == "" {
		return "", false
	}
	return v.Recipient, true
}

// EnvNamespace resolves an env's delivery namespace.
func (e RegistryProjectEntry) EnvNamespace(env string) (string, bool) {
	v, ok := e.Envs[env]
	if !ok || v.Namespace == "" {
		return "", false
	}
	return v.Namespace, true
}

// ProjectRegistry is the whole projects.json: project pubkey → entry. Admins edit
// this via `sealdctl admin env set/rm`, then commit it (CODEOWNERS-gated MR) —
// restoring the reviewed-config gate the v4 repo.yaml collapse moved out of git.
type ProjectRegistry map[string]RegistryProjectEntry

// ParseProjectRegistry parses projects.json bytes (empty/"" → empty registry).
func ParseProjectRegistry(data []byte) (ProjectRegistry, error) {
	r := ProjectRegistry{}
	if len(data) == 0 {
		return r, nil
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse projects.json: %w", err)
	}
	return r, nil
}

// MarshalJSON2 renders the registry as pretty, stable JSON (the form committed to
// git). Named MarshalJSON2 to avoid overriding the map's default json.Marshal.
func (r ProjectRegistry) MarshalJSON2() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// entry returns (creating if absent) the mutable entry for pub, enforcing that an
// existing entry's project_id is not silently changed.
func (r ProjectRegistry) entry(pub string, projectID int64) (RegistryProjectEntry, error) {
	e, ok := r[pub]
	if !ok {
		return RegistryProjectEntry{
			ProjectID: projectID,
			Envs:      map[string]RegistryEnv{},
		}, nil
	}
	if projectID != 0 && e.ProjectID != 0 && e.ProjectID != projectID {
		return RegistryProjectEntry{}, fmt.Errorf("project %s already registered with project_id %d, not %d (refusing to change identity)", pub, e.ProjectID, projectID)
	}
	if e.Envs == nil {
		e.Envs = map[string]RegistryEnv{}
	}
	return e, nil
}

// SetEnvV2 adds/updates a first-class environment. FAILS CLOSED without
// a recipient (nothing to seal to) or a namespace (nowhere to deliver). The
// recipient is the env's OWN key — distinct per env even on a shared cluster.
func (r ProjectRegistry) SetEnvV2(pub string, projectID int64, env string, cfg RegistryEnv) error {
	e, err := r.entry(pub, projectID)
	if err != nil {
		return err
	}
	if cfg.Recipient == "" {
		return fmt.Errorf("env %q: recipient is required (the env's age public key to seal to)", env)
	}
	if cfg.Namespace == "" {
		return fmt.Errorf("env %q: namespace is required (the delivery target)", env)
	}
	if cfg.Cluster == "" {
		return fmt.Errorf("env %q: cluster is required (which physical cluster runs it)", env)
	}
	if cfg.MinLevel <= 0 {
		return fmt.Errorf("env %q: min_level must be positive, got %d", env, cfg.MinLevel)
	}
	e.Envs[env] = cfg
	r[pub] = e
	return nil
}

// RemoveEnv deletes an environment. Removing an absent env is an error (typo guard
// — a silent no-op could mask a wrong env name).
func (r ProjectRegistry) RemoveEnv(pub, env string) error {
	e, ok := r[pub]
	if !ok {
		return fmt.Errorf("project %s not in registry", pub)
	}
	if _, ok := e.Envs[env]; !ok {
		return fmt.Errorf("env %q not present for project %s (nothing to remove)", env, pub)
	}
	delete(e.Envs, env)
	r[pub] = e
	return nil
}
