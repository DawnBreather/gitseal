package client

import (
	"encoding/base64"
	"fmt"
	"sort"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// MigrateBundleToV4 re-seals a v3 (or v2) bundle to v4, in place. Unlike
// v2→v3 (a ciphertext-preserving struct transform), v4 changes the embedded
// anti-splice discriminator from the numeric project_id to the project PUBKEY,
// which lives UNDER the AEAD — so this genuinely DECRYPTS and RE-ENCRYPTS:
//
//	for each env section:
//	  for each entry:
//	    plaintext = UnsealVerified(ct, humanIdentity, <embedded id>)   // decrypt v2/v3
//	    ct' = SealMultiV4(plaintext, [human, cluster[env]], ownerPubkey)  // re-encrypt v4
//	  re-sign the section over CanonicalSectionBytesV4(ownerPubkey, env, entries')
//
// PLAINTEXT is preserved (proven by decrypt-v4 == original); per-env cluster
// isolation is preserved (each env re-encrypts to [human, its own cluster]); the
// numeric project_id is GONE from the output — the pubkey is the sole identity.
//
// Inputs: humanIdentity (the repo private key, to decrypt v2/v3 — extracted from
// the broker keystore Secret at run time); ownerPubkey (the repo recipient, the v4
// discriminant + a recipient so the broker/human can still unseal); clusters +
// envCluster (from repo.yaml, to pick each env's cluster recipient); signer (SSH
// key for attribution). A v1 flat bundle is refused. Already-v4 is re-signed.
func MigrateBundleToV4(path, humanIdentity, ownerPubkey string, clusters, envCluster map[string]string, signer *SSHSigner) (*MigrateResult, error) {
	b, err := LoadBundle(path)
	if err != nil {
		return nil, err
	}
	if !IsPerEnvVersion(b.Version) {
		return nil, fmt.Errorf("migrate-v4: %s is version %q; only a per-env bundle (v2/v3/v4) can be migrated", path, b.Version)
	}
	if len(b.Envs) == 0 {
		return nil, fmt.Errorf("migrate-v4: %s has no env sections", path)
	}
	if ownerPubkey == "" || humanIdentity == "" {
		return nil, fmt.Errorf("migrate-v4: ownerPubkey and humanIdentity are required")
	}

	// numeric id to decrypt v2/v3 entries: v2 carries it; v3 uses the embedded id
	// (we pass the bundle's own field, which v3 dropped → 0 → we must read it from
	// the ciphertext). Since v3 has no in-file id, we decrypt by trying the human
	// identity and letting UnsealVerified read+return the embedded id itself. But
	// UnsealVerified REQUIRES a wantProjectID to assert against, so for v3 we accept
	// whatever is embedded by first parsing it. Simplest correct path: for v2 use
	// b.ProjectID; for v3 the caller has no numeric id, so we decrypt v3 via the
	// pubkey-agnostic Unseal that only needs the key — see decryptForMigrate.
	fromVersion := b.Version
	res := &MigrateResult{Fingerprint: signer.Fingerprint(), FromVersion: fromVersion}

	for env, sec := range b.Envs {
		clusterName, ok := envCluster[env]
		if !ok {
			return nil, fmt.Errorf("migrate-v4: env %q has no cluster mapping in repo.yaml", env)
		}
		clusterRcpt, ok := clusters[clusterName]
		if !ok {
			return nil, fmt.Errorf("migrate-v4: cluster %q for env %q has no recipient in repo.yaml", clusterName, env)
		}
		recipients := []string{ownerPubkey, clusterRcpt}

		newEntries := make(map[string]string, len(sec.Entries))
		for _, name := range sortedKeys(sec.Entries) {
			ct := b.EnvCiphertext(env, name)
			if ct == nil {
				return nil, fmt.Errorf("migrate-v4: %s/%s unreadable (bad base64)", env, name)
			}
			pt, minLevel, err := decryptForMigrate(ct, humanIdentity, b.ProjectID)
			if err != nil {
				return nil, fmt.Errorf("migrate-v4: decrypt %s/%s: %w", env, name, err)
			}
			nct, err := crypto.SealMultiV4(pt, recipients, ownerPubkey, name, minLevel)
			if err != nil {
				return nil, fmt.Errorf("migrate-v4: re-seal %s/%s: %w", env, name, err)
			}
			newEntries[name] = base64.StdEncoding.EncodeToString(nct)
		}

		// sign the re-sealed section over the v4 canonical bytes (bound to pubkey).
		sig, err := signer.Sign(CanonicalSectionBytesV4(ownerPubkey, env, newEntries))
		if err != nil {
			return nil, fmt.Errorf("migrate-v4: sign env %q: %w", env, err)
		}
		b.Envs[env] = EnvSection{
			Entries: newEntries,
			Sig:     &EnvSectionSig{By: res.Fingerprint, Sig: sig},
		}
		res.EnvsSigned = append(res.EnvsSigned, env)
	}
	sort.Strings(res.EnvsSigned)

	// normalize to v4 (drop any denormalized v2 fields + section clusters already
	// dropped by the rebuild above).
	b.Version = BundleVersionV4
	b.ProjectID = 0
	b.MinAccessLevel = 0
	b.Recipient = ""
	b.Recipients = nil
	b.Entries = nil

	if err := writeBundle(path, b); err != nil {
		return nil, err
	}
	return res, nil
}

// decryptForMigrate decrypts a v2/v3 entry with the human identity, returning the
// plaintext + the embedded min access level (to preserve it on re-seal). v2 carries
// a numeric project_id in-file (v2ProjectID); v3 dropped it, but the id is still
// embedded in the ciphertext — crypto.UnsealVerified asserts against a supplied id,
// so for v3 (v2ProjectID == 0) we read the embedded id first and assert it against
// itself (a tautology that still exercises the AEAD + returns the level).
func decryptForMigrate(ct []byte, humanIdentity string, v2ProjectID int64) ([]byte, int, error) {
	if v2ProjectID != 0 {
		return crypto.UnsealVerified(ct, []byte(humanIdentity), v2ProjectID)
	}
	// v3: discover the embedded id, then decrypt asserting it.
	embedded, err := crypto.EmbeddedProjectID(ct, []byte(humanIdentity))
	if err != nil {
		return nil, 0, err
	}
	return crypto.UnsealVerified(ct, []byte(humanIdentity), embedded)
}
