package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// Bundle schema versions.
//
//	v1: flat {recipient, entries}.
//	v2: {project_id, min_access_level, recipients{}, envs.<env>.{cluster, entries}}.
//	v3: NORMALIZED — {envs.<env>.{entries, sig}} only. The denormalized
//	    fields (project_id / min_access_level / recipients / env.cluster) are DROPPED:
//	    project_id + level are the AEAD truth (embedded per entry); recipients +
//	    env→cluster live in the registry (broker), keyed by the project pubkey in
//	    .seald/repo.yaml. The file states only which secrets exist per env, plus who
//	    signed each section (Stage B).
//	v4 (current): SAME file shape as v3, but each entry's AEAD envelope
//	    embeds the project PUBKEY (recipient) as the anti-splice discriminator
//	    instead of the numeric project_id, and section signatures bind to the pubkey.
//	    This lets .seald/repo.yaml collapse to `recipient:` only — the pubkey is the
//	    sole project identity. The bundle JSON is byte-shape-identical to v3 (version
//	    string aside); the difference is entirely in the ciphertext discriminator +
//	    the signature domain.
const (
	BundleVersionV1 = "v1"
	BundleVersionV2 = "v2"
	BundleVersionV3 = "v3"
	BundleVersionV4 = "v4"
)

// IsPerEnvVersion reports whether a bundle version uses the per-env section shape
// (envs.<env>.entries) — v2, v3, v4. v1 is the flat legacy shape. This is the
// single predicate every per-env code path gates on, so adding a version can't
// leave a stale `== V2 || == V3` behind (the v4 rollout hazard).
func IsPerEnvVersion(v string) bool {
	return v == BundleVersionV2 || v == BundleVersionV3 || v == BundleVersionV4
}

// EnvSectionSig is a per-env-section signature (Stage B): the SSH-key
// fingerprint of the signer + the detached signature over the section's canonical
// bytes. Attribution lives BESIDE the entries map (never inside it) so the
// entries stay a clean KEY→ciphertext view. Empty on a v1/v2 bundle.
type EnvSectionSig struct {
	By  string `json:"by,omitempty"`  // "SHA256:<ssh fingerprint>" of the signer
	Sig string `json:"sig,omitempty"` // base64 detached SSH signature over the canonical section bytes
}

// EnvSection is one env's slice of a SealedBundle: its name→ciphertext entries
// (+ v3 signature). Every ciphertext is sealed to EXACTLY [human-repo-key, that
// env's cluster key] — the per-cluster isolation boundary, enforced by
// CRYPTO (the recipient stanzas inside each ciphertext), not by any label. The
// v2 `cluster` label was always advisory (L1) and is dropped in v3; the env→cluster
// mapping is authoritative in the registry.
type EnvSection struct {
	Cluster string            `json:"cluster,omitempty"` // v2 only (advisory); absent in v3
	Entries map[string]string `json:"entries"`
	Sig     *EnvSectionSig    `json:"sig,omitempty"` // v3 attribution
}

// SealedBundle is one committed file holding many sealed secrets for a repo,
// at any path. `kind: SealedBundle` deliberately differs from a k8s
// `kind: Secret`/bitnami `SealedSecret` so ArgoCD/controllers never try to
// consume it — gitseal bundles are for HUMAN unseal only.
// LoadBundle branches on Version; v1/v2 still read (migration), seal writes v3.
type SealedBundle struct {
	Kind    string `json:"kind"`    // always "SealedBundle"
	Version string `json:"version"` // "v1" | "v2" | "v3"

	// v1/v2 denormalized fields — READ for migration, never WRITTEN by v3 seal.
	ProjectID      int64             `json:"project_id,omitempty"`
	MinAccessLevel int               `json:"min_access_level,omitempty"`
	Recipient      string            `json:"recipient,omitempty"`  // v1 flat recipient (advisory)
	Entries        map[string]string `json:"entries,omitempty"`    // v1 flat entries
	Recipients     map[string]string `json:"recipients,omitempty"` // v2 registry (advisory)

	// v2/v3: per-env sections.
	Envs map[string]EnvSection `json:"envs,omitempty"`
}

// Names returns the secret names in the bundle.
func (b *SealedBundle) Names() []string {
	names := make([]string, 0, len(b.Entries))
	for n := range b.Entries {
		names = append(names, n)
	}
	return names
}

// Ciphertext returns the raw (base64-decoded) age blob for a name (nil if
// absent). v1 flat-entries accessor.
func (b *SealedBundle) Ciphertext(name string) []byte {
	enc, ok := b.Entries[name]
	if !ok {
		return nil
	}
	return decodeEntry(enc)
}

// EnvCiphertext returns the raw (base64-decoded) age blob for a name inside a
// v2 env section (nil if the env or the name is absent). Mirrors Ciphertext's
// decode, selecting envs[env].entries[name].
func (b *SealedBundle) EnvCiphertext(env, name string) []byte {
	sec, ok := b.Envs[env]
	if !ok {
		return nil
	}
	enc, ok := sec.Entries[name]
	if !ok {
		return nil
	}
	return decodeEntry(enc)
}

// SelectCiphertext resolves the raw (base64-decoded) age blob for (env, name),
// picking the right accessor for the bundle version: a v2 bundle selects the
// per-env section (envs[env].entries[name] via EnvCiphertext); a v1 (flat) or
// legacy bundle ignores env and falls back to the flat Ciphertext(name). Returns
// nil when the env/name is absent — so the caller never sends a wrong-env blob.
// This is the only selector change the human unseal path needs for v2; the
// broker POST is unchanged (it still receives one ciphertext + project_id + name).
func (b *SealedBundle) SelectCiphertext(env, name string) []byte {
	if IsPerEnvVersion(b.Version) {
		return b.EnvCiphertext(env, name)
	}
	return b.Ciphertext(name)
}

// decodeEntry base64-decodes a stored (present) entry value, returning nil on
// malformed input — the shared decode behind Ciphertext and EnvCiphertext.
func decodeEntry(enc string) []byte {
	ct, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil
	}
	return ct
}

// LoadBundle reads a SealedBundle file.
func LoadBundle(path string) (*SealedBundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	return ParseBundle(data)
}

// ParseBundle parses SealedBundle bytes (the file-independent core of LoadBundle),
// applying the same kind/version validation + section normalization. Used to
// parse bundle content that never lives on disk — e.g. `git show <rev>:<path>`
// output in the write-authz gate.
func ParseBundle(data []byte) (*SealedBundle, error) {
	var b SealedBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}
	if b.Kind != "SealedBundle" {
		return nil, fmt.Errorf("not a SealedBundle (kind=%q)", b.Kind)
	}
	switch b.Version {
	case BundleVersionV3, BundleVersionV4:
		// v3/v4 are normalized: only envs sections are required (NO recipients
		// registry, NO project_id/min_access_level). v4 differs from v3 only in the
		// ciphertext discriminator (embedded pubkey vs numeric id) + signature domain
		// — the JSON shape is identical, so they parse the same way.
		if b.Envs == nil {
			return nil, fmt.Errorf("malformed %s bundle: missing envs", b.Version)
		}
		for env, sec := range b.Envs {
			if sec.Entries == nil {
				sec.Entries = map[string]string{}
				b.Envs[env] = sec
			}
		}
	case BundleVersionV2:
		// A v2 bundle MUST carry both the recipients registry and the env
		// sections; a v2 file missing either is malformed (a v1 bundle
		// mislabelled, or a truncated/edited file) — refuse it rather than
		// silently degrade to an empty bundle.
		if b.Recipients == nil || b.Envs == nil {
			return nil, fmt.Errorf("malformed v2 bundle: missing recipients or envs")
		}
		for env, sec := range b.Envs {
			if sec.Entries == nil {
				sec.Entries = map[string]string{}
				b.Envs[env] = sec
			}
		}
	default: // "v1" or "" (legacy) — flat entries.
		if b.Entries == nil {
			b.Entries = map[string]string{}
		}
	}
	return &b, nil
}

// SealBundle seals `secrets` (name→plaintext) into the bundle at path and writes
// it. Each value is individually age-sealed to `recipient` with `projectID` and
// `minLevel` embedded in its AEAD envelope.
//
//   - replace (merge=false, the default): the bundle's entries become EXACTLY the
//     given secrets (removed keys dropped).
//   - merge=true: add/overwrite the given keys, keep the rest.
//   - prune=true (only with merge): also remove keys absent from `secrets`
//     (equivalent to replace, but explicit).
//
// Returns a name-level diff (added/removed/kept) vs the prior bundle.
func SealBundle(path, recipient string, projectID int64, minLevel int, secrets map[string]string, merge, prune bool) (NameDiff, error) {
	// load prior (if any) for the diff + merge base
	prior := &SealedBundle{Entries: map[string]string{}}
	if existing, err := LoadBundle(path); err == nil {
		prior = existing
		// AUDIT v2 #3: never merge entries across repos. If the existing bundle
		// belongs to a different project, merging would carry over another repo's
		// (differently-keyed, differently-leveled) ciphertexts. Refuse.
		if merge && prior.ProjectID != 0 && prior.ProjectID != projectID {
			return NameDiff{}, fmt.Errorf("refusing --merge: existing bundle project_id %d != target %d", prior.ProjectID, projectID)
		}
	}
	oldNames := prior.Names()

	// seal each new/updated value
	newEntries := map[string]string{}
	if merge {
		for k, v := range prior.Entries {
			newEntries[k] = v
		}
	}
	for name, val := range secrets {
		ct, err := crypto.SealWithLevel([]byte(val), recipient, projectID, name, minLevel)
		if err != nil {
			return NameDiff{}, fmt.Errorf("seal %s: %w", name, err)
		}
		newEntries[name] = base64.StdEncoding.EncodeToString(ct)
	}
	if merge && prune {
		for k := range newEntries {
			if _, ok := secrets[k]; !ok {
				delete(newEntries, k)
			}
		}
	}

	out := &SealedBundle{
		Kind:           "SealedBundle",
		Version:        "v1",
		ProjectID:      projectID,
		MinAccessLevel: minLevel,
		Recipient:      recipient,
		Entries:        newEntries,
	}
	if err := writeBundle(path, out); err != nil {
		return NameDiff{}, err
	}

	newNames := out.Names()
	sort.Strings(newNames)
	return DiffNames(oldNames, newNames), nil
}

// SealBundleV2 seals a resolved env→(KEY→plaintext) matrix into a v2 bundle at
// path. Each value is sealed to EXACTLY [human, clusters[envCluster[env]]] via
// crypto.SealMulti, so every entry in an env section is openable only by the
// human recipient or that env's cluster key — the per-cluster isolation
// boundary. The written bundle's `recipients` registry is {human, ...clusters}.
//
// NO-NONCE-CHURN RULE (reseal-if-absent): plaintext is never stored and age
// sealing is non-deterministic, so a stored ciphertext cannot be compared to a
// new plaintext without the cluster identity (which the authoring path does not
// hold). The provably-minimal rule this implements is therefore:
//
//	for each (env, key): if the PRIOR bundle (v2, same env section) already has a
//	ciphertext for that key, copy those bytes VERBATIM; otherwise seal fresh.
//
// So a reseal that re-supplies an unchanged key set leaves every entry
// byte-identical (no nonce churn), and adding a new key seals only the new key.
// A key that must actually be rotated is rotated by first removing it from the
// prior bundle (it is then absent → resealed) — deliberate, not incidental.
// Keys absent from `resolved` for an env are dropped from that section
// (declarative replace, mirroring v1 SealBundle's non-merge behavior).
//
// Returns a per-env name-level NameDiff (added/removed/kept vs the prior bundle).
func SealBundleV2(path, human string, clusters, envCluster map[string]string,
	projectID int64, minLevel int, resolved map[string]map[string]string) (map[string]NameDiff, error) {

	// Load prior bundle for the no-churn carry-over (a v2 OR v3 bundle has per-env
	// ciphertexts to reuse; a v1 or absent bundle → reseal everything). A v2 bundle
	// still carries project_id we can cross-check; v3 dropped it (project_id is the
	// AEAD truth now), so there is nothing to cross-check for v3 — the carry-over is
	// per-(env,key) verbatim, and an env→cluster REMAP is handled by the deliberate
	// remove-then-reseal ritual (L10), never silently.
	prior := map[string]EnvSection{}
	if existing, err := LoadBundle(path); err == nil {
		if existing.Version == BundleVersionV2 || existing.Version == BundleVersionV3 {
			if existing.ProjectID != 0 && existing.ProjectID != projectID {
				return nil, fmt.Errorf("refusing reseal: existing bundle project_id %d != target %d", existing.ProjectID, projectID)
			}
			prior = existing.Envs
		}
	}

	// Start from the prior sections so an ENV-SCOPED seal (resolved covers only a
	// subset of envs) PRESERVES the untouched env sections byte-identical rather
	// than dropping them. Envs present in `resolved` are rebuilt below (per-key
	// replace + no-nonce-churn); envs absent from `resolved` are carried verbatim.
	// The full-fan-out path (resolved covers every env) is unaffected — it
	// overwrites every section anyway.
	envs := make(map[string]EnvSection, len(prior)+len(resolved))
	for env, sec := range prior {
		envs[env] = sec
	}
	diffs := make(map[string]NameDiff, len(resolved))

	// Deterministic env order (stable output; the per-env map iteration below is
	// resolved into a fresh Entries map so key order in JSON is map-sorted anyway).
	envNames := make([]string, 0, len(resolved))
	for env := range resolved {
		envNames = append(envNames, env)
	}
	sort.Strings(envNames)

	for _, env := range envNames {
		clusterName, ok := envCluster[env]
		if !ok {
			return nil, fmt.Errorf("no cluster mapped for env %q", env)
		}
		clusterRecip, ok := clusters[clusterName]
		if !ok {
			return nil, fmt.Errorf("cluster %q (env %q) has no recipient", clusterName, env)
		}
		recipients := []string{human, clusterRecip}

		priorSec := prior[env]
		// v2 prior sections carry a `cluster` label; v3 does not. Carry-over is safe
		// only if the env still seals to the SAME cluster as the prior bytes. For a
		// v2 prior we can check the label; for a v3 prior (no label) we assume a
		// stable env→cluster mapping (the common case) — an env→cluster REMAP must be
		// done via the deliberate remove-then-reseal ritual (L10), which drops the
		// key so it's absent → resealed fresh. So: carry verbatim when the prior key
		// exists AND (no v2 label OR the v2 label matches this cluster).
		sameCluster := priorSec.Cluster == "" || priorSec.Cluster == clusterName
		entries := make(map[string]string, len(resolved[env]))
		for name, val := range resolved[env] {
			if sameCluster && priorSec.Entries != nil {
				if enc, ok := priorSec.Entries[name]; ok {
					entries[name] = enc
					continue
				}
			}
			ct, err := crypto.SealMulti([]byte(val), recipients, projectID, name, minLevel)
			if err != nil {
				return nil, fmt.Errorf("seal %s/%s: %w", env, name, err)
			}
			entries[name] = base64.StdEncoding.EncodeToString(ct)
		}
		// v3 EnvSection: entries only (no cluster label). Preserve a prior signature
		// pointer position for Stage B; Stage A leaves Sig nil.
		envs[env] = EnvSection{Entries: entries}

		oldNames := namesOf(priorSec.Entries)
		newNames := namesOf(entries)
		sort.Strings(oldNames)
		sort.Strings(newNames)
		diffs[env] = DiffNames(oldNames, newNames)
	}

	// v3: NORMALIZED — no project_id/min_access_level/recipients/cluster.
	// project_id + level are embedded in each AEAD envelope (crypto truth);
	// recipients + env→cluster live in the registry keyed by the project pubkey.
	out := &SealedBundle{
		Kind:    "SealedBundle",
		Version: BundleVersionV3,
		Envs:    envs,
	}
	if err := writeBundle(path, out); err != nil {
		return nil, err
	}
	return diffs, nil
}

// namesOf returns the (unsorted) keys of an entries map.
func namesOf(entries map[string]string) []string {
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	return names
}

func writeBundle(path string, b *SealedBundle) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}
