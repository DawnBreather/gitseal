package client

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// ageParseIdentity parses an "AGE-SECRET-KEY-1…" string and returns its public
// recipient ("age1…"), or an error if it isn't a valid X25519 identity.
func ageParseIdentity(identity string) (string, error) {
	id, err := age.ParseX25519Identity(identity)
	if err != nil {
		return "", fmt.Errorf("not a valid age identity: %w", err)
	}
	return id.Recipient().String(), nil
}

// RecipientFromIdentity is the exported form (gitseal-controller adopts an existing
// materializer key by deriving its public recipient to register).
func RecipientFromIdentity(identity string) (string, error) { return ageParseIdentity(identity) }

// jsonMarshalIndent marshals a key file with stable 2-space indentation + newline.
func jsonMarshalIndent(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// OnboardInputs is the registry + identity context an onboard needs: the target
// project id + the fleet's environments: env → {cluster, namespace,
// min_level, recipient}. The env recipients + namespaces are shared fleet-wide (a
// single per-env materializer decrypts every project's section for that env), so a
// new project copies them from an existing registry entry (--clusters-from-registry).
type OnboardInputs struct {
	ProjectID  int64
	HumanRecip string                 // vestigial (the minted key is the repo recipient)
	Envs       map[string]RegistryEnv // env → {cluster, namespace, min_level, recipient}
}

// OnboardResult reports what an onboard did: the repo.yaml text the target repo
// should commit, the repo's public recipient, and whether a key was minted this
// run (false = idempotent no-op because the key already existed).
type OnboardResult struct {
	RepoYAML  string
	Recipient string
	Minted    bool
	KeyPath   string
}

// PlanOnboard is the pure core of `sealdctl admin onboard`. It:
//   - validates the registry (every env maps to a cluster with a recipient);
//   - if <keystore>/<pid>.key.json is ABSENT (or force), mints a fresh per-repo
//
// age key and writes a v2 key file (the RAW identity, no KEK) — an
//
//	  APPEND to the keystore dir, never a hand-edit of a shared blob;
//	- if the key file already EXISTS and !force, NO-OPS (reuses the existing
//	  recipient) so a re-run can't mint a second key whose recipient no longer
//	  matches the committed repo.yaml (the double-mint→dead-key footgun);
//	- returns the repo.yaml (project_id + recipient + clusters + env_cluster +
//	  env_min_level) for the target repo to commit.
//
// keystoreDir is a LOCAL staging dir the CLI then syncs into the broker-owned,
// out-of-band keystore Secret (`--apply`); the private key never enters git.
// force=true deliberately rotates (re-mints + rewrites the key file).
func PlanOnboard(in OnboardInputs, keystoreDir string, force bool) (*OnboardResult, error) {
	if in.ProjectID <= 0 {
		return nil, fmt.Errorf("onboard: project id must be > 0")
	}
	// NOTE: HumanRecip is vestigial (v4 — the MINTED key is the repo's recipient,
	// not a pre-known one); no longer required. Kept on the struct for the legacy
	// repo.yaml path's informational copy.
	// validate registry: every env has a recipient + namespace.
	for _, env := range sortedKeys(in.Envs) {
		cfg := in.Envs[env]
		if cfg.Recipient == "" {
			return nil, fmt.Errorf("onboard: env %q has no recipient", env)
		}
		if cfg.Namespace == "" {
			return nil, fmt.Errorf("onboard: env %q has no namespace", env)
		}
	}

	if err := os.MkdirAll(keystoreDir, 0755); err != nil {
		return nil, fmt.Errorf("onboard: keystore dir: %w", err)
	}
	keyPath := filepath.Join(keystoreDir, KeyFileName(in.ProjectID))

	res := &OnboardResult{KeyPath: keyPath}

	if _, statErr := os.Stat(keyPath); statErr == nil && !force {
		// Idempotent no-op: reuse the existing key's recipient.
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("onboard: read existing key: %w", err)
		}
		kf, err := ParseKeyFile(data)
		if err != nil {
			return nil, fmt.Errorf("onboard: existing key file is invalid (use --rotate to replace): %w", err)
		}
		recip, err := kf.deriveRecipient()
		if err != nil {
			return nil, fmt.Errorf("onboard: %w", err)
		}
		res.Recipient = recip
		res.Minted = false
	} else {
		// Mint (first onboard, or forced rotate). v2: store the RAW identity — no
		// KEK; the keystore lives in the broker's out-of-band Secret.
		kp, err := crypto.GenerateRepoKey()
		if err != nil {
			return nil, err
		}
		kf := NewKeyFileV2(in.ProjectID, kp.Identity)
		if err := writeKeyFileAtomic(keyPath, kf); err != nil {
			return nil, err
		}
		res.Recipient = kp.Recipient
		res.Minted = true
	}

	res.RepoYAML = renderRepoYAML(in, res.Recipient)
	return res, nil
}

// deriveRecipient resolves the key file's identity (v1 or v2) and returns its public
// recipient (used by the idempotent no-op path to echo the existing repo's recipient).
func (kf *KeyFile) deriveRecipient() (string, error) {
	identity, err := kf.Identity()
	if err != nil {
		return "", err
	}
	return ageParseIdentity(identity)
}

// renderRepoYAML produces the committed.seald/repo.yaml — v4:
// RECIPIENT-ONLY. The project's age public key is its sole identity; project_id,
// clusters, env_cluster and env_min_level all live in the broker registry
// (projects.json, git-tracked ConfigMap), fetched by seal/verify as a cached
// snapshot. `onboard` emits the matching registry entry separately (see
// RegistryEntryFor) so the operator commits both in one go.
func renderRepoYAML(_ OnboardInputs, recipient string) string {
	var b strings.Builder
	b.WriteString("# gitseal repo config (generated by `sealdctl admin onboard`). Commit\n")
	b.WriteString("# this — the recipient is a PUBLIC key. It is the project's SOLE identity;\n")
	b.WriteString("# project_id / clusters / env_cluster / env_min_level live in the broker\n")
	b.WriteString("# registry (projects.json), fetched as a cached snapshot. Unsealing goes\n")
	b.WriteString("# through the in-cluster broker (live GitLab-membership gated). See\n")
	b.WriteString("# infra-repo/.docs.\n")
	fmt.Fprintf(&b, "recipient: %s\n", recipient)
	return b.String()
}

// RegistryEntryFor builds the broker-registry entry (projects.json) for a freshly
// onboarded project, keyed by its minted public recipient. This is
// what `admin onboard` prints alongside the recipient-only repo.yaml so the
// operator commits BOTH — the repo's identity AND its registry row — in one flow,
// with no hand-editing of projects.json. Reuses the ProjectRegistry mutation, so
// it fails closed on an env whose cluster has no recipient (same guard as
// `admin env set`). Returns a single-entry registry ready to merge into the
// git-tracked projects.json.
func RegistryEntryFor(in OnboardInputs, recipient string) (ProjectRegistry, error) {
	reg := ProjectRegistry{}
	for _, env := range sortedKeys(in.Envs) {
		cfg := in.Envs[env]
		if cfg.MinLevel == 0 {
			cfg.MinLevel = crypto.DefaultMinAccessLevel
		}
		if err := reg.SetEnvV2(recipient, in.ProjectID, env, cfg); err != nil {
			return nil, err
		}
	}
	return reg, nil
}

// writeKeyFileAtomic writes the key file 0600 via a temp-file + rename so a
// crash can't leave a half-written key.
func writeKeyFileAtomic(path string, kf *KeyFile) error {
	data, err := jsonMarshalIndent(kf)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
