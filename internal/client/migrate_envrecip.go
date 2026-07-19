package client

import (
	"encoding/base64"
	"fmt"
	"sort"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// ReSealToEnvRecipients re-seals a v4 bundle from whatever recipients it currently
// uses (CLUSTER, pre) to per-ENV recipients. For each env
// section it decrypts every entry with the human/project key and re-encrypts to
// [ownerPubkey, envRecipients[env]], then re-signs the section. Because prod and
// preprod now get DIFFERENT recipients (even on the same physical cluster), the
// prod section becomes undecryptable by the preprod key — real intra-cluster
// isolation. PLAINTEXT is preserved (decrypt→re-encrypt of the same bytes); the
// embedded owner pubkey (v4 anti-splice discriminator) is unchanged, so
// materialize/unseal still verify it.
//
// The bundle is already v4, so entries decrypt via UnsealVerifiedByKey (the
// embedded discriminator is the pubkey, not a numeric id). humanIdentity is the
// project private key (extracted out-of-band from the broker keystore for the
// migration). envRecipients must cover every env section in the bundle.
func ReSealToEnvRecipients(path, humanIdentity, ownerPubkey string, envRecipients map[string]string, signer *SSHSigner) (*MigrateResult, error) {
	b, err := LoadBundle(path)
	if err != nil {
		return nil, err
	}
	if b.Version != BundleVersionV4 {
		return nil, fmt.Errorf("re-seal-env: %s is version %q, expected v4 (run migrate-v4 first)", path, b.Version)
	}
	if ownerPubkey == "" || humanIdentity == "" {
		return nil, fmt.Errorf("re-seal-env: ownerPubkey and humanIdentity are required")
	}

	res := &MigrateResult{Fingerprint: signer.Fingerprint(), FromVersion: b.Version}

	for env, sec := range b.Envs {
		envRcpt, ok := envRecipients[env]
		if !ok || envRcpt == "" {
			return nil, fmt.Errorf("re-seal-env: no recipient for env %q (registry env.recipient missing)", env)
		}
		recipients := []string{ownerPubkey, envRcpt}

		newEntries := make(map[string]string, len(sec.Entries))
		for _, name := range sortedKeys(sec.Entries) {
			ct := b.EnvCiphertext(env, name)
			if ct == nil {
				return nil, fmt.Errorf("re-seal-env: %s/%s unreadable (bad base64)", env, name)
			}
			// bundle is v4 → decrypt by pubkey (the human/project key is a recipient).
			id := append([]byte(nil), humanIdentity...)
			pt, minLevel, err := crypto.UnsealVerifiedByKey(ct, id, ownerPubkey)
			if err != nil {
				return nil, fmt.Errorf("re-seal-env: decrypt %s/%s: %w", env, name, err)
			}
			nct, err := crypto.SealMultiV4(pt, recipients, ownerPubkey, name, minLevel)
			if err != nil {
				return nil, fmt.Errorf("re-seal-env: re-seal %s/%s: %w", env, name, err)
			}
			newEntries[name] = base64.StdEncoding.EncodeToString(nct)
		}

		sig, err := signer.Sign(CanonicalSectionBytesV4(ownerPubkey, env, newEntries))
		if err != nil {
			return nil, fmt.Errorf("re-seal-env: sign env %q: %w", env, err)
		}
		b.Envs[env] = EnvSection{Entries: newEntries, Sig: &EnvSectionSig{By: res.Fingerprint, Sig: sig}}
		res.EnvsSigned = append(res.EnvsSigned, env)
	}
	sort.Strings(res.EnvsSigned)

	if err := writeBundle(path, b); err != nil {
		return nil, err
	}
	return res, nil
}
