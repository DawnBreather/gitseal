package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// RepoConfig is .seald/repo.yaml — the per-repo binding committed to the repo.
//
// v1: project_id + recipient (the human recipient) + optional min_access_level.
// v2 additionally declares the per-cluster registry used by the
// materializer/authoring tools: a `clusters` map (name → age recipient) and an
// `env_cluster` map (env → cluster name). Recipient stays the human recipient
// on every entry of every env; clusters are the per-env isolation keys.
type RepoConfig struct {
	ProjectID      int64  `yaml:"project_id"`
	Recipient      string `yaml:"recipient"`
	MinAccessLevel int    `yaml:"min_access_level,omitempty"` // optional repo default

	// v2 cluster registry (absent in v1 repo.yaml → both nil).
	Clusters   map[string]string `yaml:"clusters,omitempty"`    // cluster name → age recipient
	EnvCluster map[string]string `yaml:"env_cluster,omitempty"` // env → cluster name

	// Write-authz policy (optional): env → GitLab access level required to CHANGE
	// that env's sealed entries. Consulted by the CI write-authz gate (verify
	// --authz). PUBLIC (a policy, not a secret) and Owner-gated (editing repo.yaml
	// itself requires Owner — see PolicyEditMinLevel). Absent → MinLevelForEnv
	// falls back to the scalar min_access_level, then to Developer (30).
	EnvMinLevel map[string]int `yaml:"env_min_level,omitempty"` // env → required level

	// (resolved from the registry snapshot, not repo.yaml): env → the env's
	// OWN age recipient (the per-env seal target) + env → delivery namespace. Empty
	// for a legacy self-contained repo.yaml (which only had cluster recipients).
	EnvRecipient map[string]string `yaml:"-"`
	EnvNamespace map[string]string `yaml:"-"`
}

// DefaultDeveloperLevel is the final fallback required level (GitLab Developer).
const DefaultDeveloperLevel = 30

// MinAccessLevelOrDefault returns the repo's default level, or Developer (30).
func (rc *RepoConfig) MinAccessLevelOrDefault() int {
	if rc.MinAccessLevel > 0 {
		return rc.MinAccessLevel
	}
	return DefaultDeveloperLevel
}

// MinLevelForEnv returns the GitLab access level required to change env's sealed
// entries: env_min_level[env] → min_access_level → Developer (30). It NEVER
// returns 0 for an unlisted env (that would let level-0 callers write) — an env
// absent from env_min_level falls through to the repo scalar/default, never to
// the map's zero value. This is the write-side mirror of the broker's read-side
// access-level check.
func (rc *RepoConfig) MinLevelForEnv(env string) int {
	if lvl, ok := rc.EnvMinLevel[env]; ok && lvl > 0 {
		return lvl
	}
	return rc.MinAccessLevelOrDefault()
}

// ClusterForEnv resolves which cluster (and thus which age recipient) an env
// seals to: env_cluster[env] → clusters[name]. It errors — never returns an
// empty recipient — if the env has no cluster mapping or the mapped cluster has
// no recipient in the registry, so callers fail closed rather than seal to
// nothing.
func (rc *RepoConfig) ClusterForEnv(env string) (name, recipient string, err error) {
	name, ok := rc.EnvCluster[env]
	if !ok {
		return "", "", fmt.Errorf("no cluster mapped for env %q in repo.yaml env_cluster", env)
	}
	recipient, ok = rc.Clusters[name]
	if !ok {
		return "", "", fmt.Errorf("cluster %q (env %q) has no recipient in repo.yaml clusters", name, env)
	}
	return name, recipient, nil
}

// LoadRepoConfig reads <repoRoot>/.seald/repo.yaml.
func LoadRepoConfig(repoRoot string) (*RepoConfig, error) {
	return LoadRepoConfigFromFile(filepath.Join(repoRoot, ".seald", "repo.yaml"))
}

// LoadRepoConfigFromFile reads a repo.yaml from an explicit path (the file-path
// core of LoadRepoConfig; used when the config is read from a sibling/registry
// path rather than ./.seald, e.g. by `admin onboard --clusters-from`).
func LoadRepoConfigFromFile(path string) (*RepoConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var rc RepoConfig
	if err := yaml.Unmarshal(data, &rc); err != nil {
		return nil, fmt.Errorf("parse repo.yaml: %w", err)
	}
	// recipient (the project pubkey) is the intrinsic, always-required identity.
	// project_id is OPTIONAL as of v4: a recipient-only repo.yaml resolves
	// project_id + clusters + levels from the broker registry snapshot
	// (ResolveRepoConfig). v2/v3-era repo.yaml still carry project_id and validate.
	if rc.Recipient == "" {
		return nil, fmt.Errorf("repo.yaml missing recipient (the project public key)")
	}
	return &rc, nil
}

// SealedFile is the committed .sealed/<NAME>.json format.
type SealedFile struct {
	Seald      string `json:"seald"`
	ProjectID  int64  `json:"project_id"`
	Name       string `json:"name"`
	Recipient  string `json:"recipient"`
	Ciphertext string `json:"ciphertext"` // base64 age blob
	SealedAt   string `json:"sealed_at"`
}

// SealToFile encrypts plaintext offline to the repo recipient and writes
// <repoRoot>/.sealed/<name>.json. No broker, no network.
func SealToFile(repoRoot string, rc *RepoConfig, name string, plaintext []byte) error {
	ct, err := crypto.Seal(plaintext, rc.Recipient, rc.ProjectID, name)
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	sf := SealedFile{
		Seald:      "v1",
		ProjectID:  rc.ProjectID,
		Name:       name,
		Recipient:  rc.Recipient,
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
		SealedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	dir := filepath.Join(repoRoot, ".sealed")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(sf, "", "  ")
	return os.WriteFile(filepath.Join(dir, name+".json"), data, 0644)
}

// LoadSealedFile reads <repoRoot>/.sealed/<name>.json as a flat v1 sealed file.
//
// A v2 SealedBundle (kind: SealedBundle, per-env `envs` sections) has NO
// top-level `ciphertext`, so blindly unmarshaling it here yields an empty
// ciphertext that the broker rejects with a misleading "decrypt failed (wrong
// repo or corrupt)" (this was L17). Detect that shape up front and fail with an
// actionable error pointing at the v2 selector, so the flat path can never
// silently feed the broker empty bytes.
func LoadSealedFile(repoRoot, name string) (*SealedFile, error) {
	data, err := os.ReadFile(filepath.Join(repoRoot, ".sealed", name+".json"))
	if err != nil {
		return nil, fmt.Errorf("read sealed file: %w", err)
	}
	// Sniff the shape before committing to the v1 struct. A SealedBundle (v1 or
	// v2) is not a flat sealed file; a v2 bundle in particular must be unsealed
	// via the per-env selector.
	var probe struct {
		Kind       string          `json:"kind"`
		Version    string          `json:"version"`
		Ciphertext string          `json:"ciphertext"`
		Envs       json.RawMessage `json:"envs"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parse sealed file: %w", err)
	}
	if probe.Kind == "SealedBundle" || probe.Version == "v2" || len(probe.Envs) > 0 {
		return nil, fmt.Errorf("%s.json is a v2 SealedBundle (per-env sections), not a flat sealed file; "+
			"unseal it with the selector: sealdctl unseal --svc %s --env <prod|preprod|staging> [--name KEY]",
			name, strings.TrimSuffix(name, ".app"))
	}
	var sf SealedFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("parse sealed file: %w", err)
	}
	if sf.Ciphertext == "" {
		return nil, fmt.Errorf("%s.json has no ciphertext (not a valid flat sealed file)", name)
	}
	return &sf, nil
}

// UnsealTarget identifies the project to the broker: v1-v3 by numeric ProjectID,
// v4 by Recipient (the project pubkey). Exactly one is set; Recipient
// wins when non-empty. Sealed into the request body by unsealBody.
type UnsealTarget struct {
	ProjectID int64
	Recipient string // v4 pubkey; empty → numeric project_id path
}

// unsealBody builds the /v1/unseal request body for a target (project_id XOR
// recipient) so the PAT and SSH transports stay in sync on the wire format.
func unsealBody(t UnsealTarget, name string, ciphertext []byte) []byte {
	m := map[string]any{
		"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
		"name":       name,
	}
	if t.Recipient != "" {
		m["recipient"] = t.Recipient
	} else {
		m["project_id"] = t.ProjectID
	}
	body, _ := json.Marshal(m)
	return body
}

// Unseal POSTs the ciphertext to the broker with the caller's PAT and returns
// the decrypted plaintext. brokerURL is the base (e.g. https://seald.example.com).
func Unseal(brokerURL, token string, target UnsealTarget, name string, ciphertext []byte) ([]byte, error) {
	// Fail before the network on an empty ciphertext: the broker would return a
	// misleading "decrypt failed (wrong repo or corrupt)" for empty bytes, which
	// masqueraded as a key mismatch (L17). A caller with no ciphertext is a bug
	// in the selection path, not a broker problem.
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("%s: empty ciphertext (nothing to unseal — check the secret name/env)", name)
	}
	body := unsealBody(target, name, ciphertext)
	req, err := http.NewRequest("POST", strings.TrimRight(brokerURL, "/")+"/v1/unseal", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-GitLab-Token", token)
	req.Header.Set("Content-Type", "application/json")
	// CF Access service-token headers, if present in env (v1: optional).
	if id := os.Getenv("SEALD_CF_CLIENT_ID"); id != "" {
		req.Header.Set("CF-Access-Client-Id", id)
		req.Header.Set("CF-Access-Client-Secret", os.Getenv("SEALD_CF_CLIENT_SECRET"))
	}

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("broker unreachable: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("broker denied (%d): %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var out struct {
		PlaintextB64 string `json:"plaintext_b64"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return nil, fmt.Errorf("bad broker response: %w", err)
	}
	pt, err := base64.StdEncoding.DecodeString(out.PlaintextB64)
	if err != nil {
		return nil, fmt.Errorf("decode plaintext: %w", err)
	}
	return pt, nil
}
