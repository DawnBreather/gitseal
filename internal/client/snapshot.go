package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// --- registry snapshot fetch + cache ---------------------------------
//
// v4 collapses .seald/repo.yaml to `recipient:` only. The operational config a
// write path still needs — project_id, clusters (cluster→recipient), env→cluster,
// env→min-level — lives in the broker registry, keyed by the project pubkey, and
// is served PUBLICLY (no secrets) at /v1/registry/snapshot. Clients fetch it once
// and cache it on disk, so `seal`/`verify`/`migrate-v4` stay usable OFFLINE after
// the first fetch (the materializer never calls this — it reads env + repo.yaml).

// registrySnapshot reuses RegistryProjectEntry (which back-compat-parses both the
// envs shape and the legacy cluster_recipients/env_cluster shape), so the
// client sees one model regardless of the registry's on-disk generation.
type registrySnapshot struct {
	Projects map[string]RegistryProjectEntry `json:"projects"`
}

// FetchProjectConfig resolves the operational RepoConfig for a project identified
// by its pubkey, from the broker registry snapshot at brokerURL, caching the raw
// snapshot at cachePath. On a network failure it falls back to the cache (offline
// after first prime). The pubkey is carried through as RepoConfig.Recipient. An
// unknown pubkey is an error (fail closed — never a zero config).
func FetchProjectConfig(brokerURL, pubkey, cachePath string) (*RepoConfig, error) {
	snap, err := loadSnapshot(brokerURL, cachePath)
	if err != nil {
		return nil, err
	}
	p, ok := snap.Projects[pubkey]
	if !ok {
		return nil, fmt.Errorf("project pubkey %s not found in registry snapshot (onboard it, or check the recipient)", pubkey)
	}
	// project into RepoConfig from the Envs model. EnvRecipient/EnvNamespace
	// are the per-env seal target + delivery ns; EnvCluster/EnvMinLevel kept for the
	// verify + env-list paths.
	rc := &RepoConfig{
		ProjectID:    p.ProjectID,
		Recipient:    pubkey,
		EnvRecipient: map[string]string{},
		EnvNamespace: map[string]string{},
		EnvCluster:   map[string]string{},
		EnvMinLevel:  map[string]int{},
	}
	for env, cfg := range p.Envs {
		rc.EnvRecipient[env] = cfg.Recipient
		rc.EnvNamespace[env] = cfg.Namespace
		rc.EnvCluster[env] = cfg.Cluster
		rc.EnvMinLevel[env] = cfg.MinLevel
	}
	return rc, nil
}

// loadSnapshot fetches /v1/registry/snapshot and writes it to cachePath. If the
// network is unavailable, it falls back to a previously cached copy — so a primed
// client works offline. A total miss (no network AND no cache) is an error.
func loadSnapshot(brokerURL, cachePath string) (*registrySnapshot, error) {
	u := strings.TrimRight(brokerURL, "/") + "/v1/registry/snapshot"
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Get(u)
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if rerr == nil {
			var snap registrySnapshot
			if jerr := json.Unmarshal(body, &snap); jerr == nil {
				writeSnapshotCache(cachePath, body) // best-effort
				return &snap, nil
			}
		}
	}
	if resp != nil {
		resp.Body.Close()
	}
	// network/parse failed → try the cache (offline path).
	if cachePath != "" {
		if data, cerr := os.ReadFile(cachePath); cerr == nil {
			var snap registrySnapshot
			if jerr := json.Unmarshal(data, &snap); jerr == nil {
				return &snap, nil
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("registry snapshot unreachable and no cache at %s: %w", cachePath, err)
	}
	return nil, fmt.Errorf("registry snapshot fetch failed (status/parse) and no usable cache at %s", cachePath)
}

func writeSnapshotCache(cachePath string, body []byte) {
	if cachePath == "" {
		return
	}
	if dir := filepath.Dir(cachePath); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	_ = os.WriteFile(cachePath, body, 0o644)
}

// ResolveRepoConfig loads <root>/.seald/repo.yaml and, if it is a v4 recipient-only
// config (missing the operational fields), fills project_id / clusters /
// env_cluster / env_min_level from the broker registry snapshot (keyed by the
// recipient pubkey), caching it at cachePath. A repo.yaml that already carries
// those fields (v2/v3-era, or a pinned override) is returned verbatim WITHOUT any
// network call — so a self-contained repo still works fully offline. This is the
// merge point that lets repo.yaml collapse to `recipient:` only.
func ResolveRepoConfig(root, brokerURL, cachePath string) (*RepoConfig, error) {
	rc, err := LoadRepoConfig(root)
	if err != nil {
		return nil, err
	}
	if rc.Recipient == "" {
		return nil, fmt.Errorf(".seald/repo.yaml has no recipient")
	}
	// self-contained already → no fetch (offline-friendly, back-compat).
	if rc.ProjectID > 0 && len(rc.EnvCluster) > 0 && len(rc.Clusters) > 0 {
		return rc, nil
	}
	// v4 recipient-only → fill from the snapshot.
	cfg, err := FetchProjectConfig(brokerURL, rc.Recipient, cachePath)
	if err != nil {
		return nil, fmt.Errorf("resolve repo config for %s: %w", rc.Recipient, err)
	}
	// repo.yaml may still pin a scalar min_access_level / recipient — keep those,
	// fill the rest from the snapshot.
	cfg.MinAccessLevel = rc.MinAccessLevel
	return cfg, nil
}

// DefaultSnapshotCachePath is where the CLI caches the registry snapshot:
// $XDG_CACHE_HOME/gitseal/registry-snapshot.json (or ~/.cache/... fallback).
func DefaultSnapshotCachePath() string {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		if home, err := os.UserHomeDir(); err == nil {
			base = filepath.Join(home, ".cache")
		} else {
			base = os.TempDir()
		}
	}
	return filepath.Join(base, "gitseal", "registry-snapshot.json")
}
