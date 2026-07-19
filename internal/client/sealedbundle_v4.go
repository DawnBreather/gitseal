package client

import (
	"encoding/base64"
	"fmt"
	"sort"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// SealBundleV4 is the SEAL-FIRST authoring path. A fresh seal holds the
// plaintext, so it emits v4 DIRECTLY — each entry sealed to [human, that env's
// recipient] with the project PUBKEY (human) embedded as the AEAD anti-splice
// discriminator. This is what the v3 path (SealBundleV2) produced only after a
// separate, private-key-requiring `migrate-v4` round-trip; emitting v4 up front
// eliminates that dance for every seald-first tenant and matches the fleet's
// committed shape (recipient-only repo.yaml + v4 bundles), so a bundle is
// materializable in one step with no numeric project_id anywhere.
//
// envRecipient maps each env to its OWN age recipient (per-env key, from
// the registry snapshot). `human` is the project pubkey (repo.yaml `recipient:`) —
// both the v4 discriminator AND a body recipient (the human/broker path opens it).
//
// NO-NONCE-CHURN (reseal-if-absent), identical to SealBundleV2 but keyed on a v4
// prior: re-supplying an unchanged key carries its ciphertext byte-verbatim; a new
// key seals fresh; envs absent from `resolved` are preserved byte-identical. So a
// v4 reseal is minimal-diff — and crucially it STAYS v4 (SealBundleV2 would have
// silently downgraded a v4 prior to v3, breaking its materializer). Signing is a
// separate step (SignBundleFileV4), mirroring seal→SignBundleFile for v3.
func SealBundleV4(path, human string, envRecipient map[string]string,
	minLevel int, resolved map[string]map[string]string) (map[string]NameDiff, error) {

	// Load a v4 prior for carry-over. A v1/v2/v3 (or absent) prior contributes no
	// reusable v4 ciphertext — a mixed-version repo must go through migrate-v4, not
	// be silently re-sealed against — so only a v4 prior seeds the carry-over.
	prior := map[string]EnvSection{}
	if existing, err := LoadBundle(path); err == nil && existing.Version == BundleVersionV4 {
		prior = existing.Envs
	}

	// Start from the prior sections so an env-scoped seal preserves untouched envs.
	envs := make(map[string]EnvSection, len(prior)+len(resolved))
	for env, sec := range prior {
		envs[env] = sec
	}
	diffs := make(map[string]NameDiff, len(resolved))

	envNames := make([]string, 0, len(resolved))
	for env := range resolved {
		envNames = append(envNames, env)
	}
	sort.Strings(envNames)

	for _, env := range envNames {
		recip, ok := envRecipient[env]
		if !ok {
			return nil, fmt.Errorf("env %q has no recipient", env)
		}
		recipients := []string{human, recip}

		priorSec := prior[env]
		entries := make(map[string]string, len(resolved[env]))
		for name, val := range resolved[env] {
			if priorSec.Entries != nil {
				if enc, ok := priorSec.Entries[name]; ok {
					entries[name] = enc // carry verbatim — no nonce churn
					continue
				}
			}
			ct, err := crypto.SealMultiV4([]byte(val), recipients, human, name, minLevel)
			if err != nil {
				return nil, fmt.Errorf("seal %s/%s: %w", env, name, err)
			}
			entries[name] = base64.StdEncoding.EncodeToString(ct)
		}
		// re-sealing an env drops its stale signature (a signer must re-sign the new
		// entry set via SignBundleFileV4); the CI authz gate rejects an unsigned/stale
		// section, so this can't silently ship.
		envs[env] = EnvSection{Entries: entries}

		oldNames := namesOf(priorSec.Entries)
		newNames := namesOf(entries)
		sort.Strings(oldNames)
		sort.Strings(newNames)
		diffs[env] = DiffNames(oldNames, newNames)
	}

	out := &SealedBundle{
		Kind:    "SealedBundle",
		Version: BundleVersionV4,
		Envs:    envs,
	}
	if err := writeBundle(path, out); err != nil {
		return nil, err
	}
	return diffs, nil
}

// SignBundleFileV4 signs each env section of the v4 bundle at path over the v4
// canonical bytes (bound to the project pubkey), writing the signature back beside
// each section. Mirrors SignBundleFile (v3) — the seal→sign split is unchanged;
// only the signed domain differs (pubkey, not numeric project_id). Returns the
// signer fingerprint.
func SignBundleFileV4(path, pubkey string, signer *SSHSigner) (string, error) {
	b, err := LoadBundle(path)
	if err != nil {
		return "", err
	}
	if b.Version != BundleVersionV4 {
		return "", fmt.Errorf("sign-v4 requires a v4 bundle; %s is %q", path, b.Version)
	}
	fp := signer.Fingerprint()
	for env, sec := range b.Envs {
		sig, err := signer.Sign(CanonicalSectionBytesV4(pubkey, env, sec.Entries))
		if err != nil {
			return "", fmt.Errorf("sign env %q: %w", env, err)
		}
		sec.Sig = &EnvSectionSig{By: fp, Sig: sig}
		b.Envs[env] = sec
	}
	if err := writeBundle(path, b); err != nil {
		return "", err
	}
	return fp, nil
}
