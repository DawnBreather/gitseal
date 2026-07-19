package client

import (
	"encoding/base64"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// BundleEntry is the wire form of one repo's KEK-wrapped key + KEK (base64).
// Mirrors the broker's bundle file shape so admin output loads directly.
type BundleEntry struct {
	WrappedKeyB64 string `json:"wrapped_key_b64"`
	KEKB64        string `json:"kek_b64"`
}

// AddRepoKey generates a fresh per-repo age keypair + KEK, wraps the private key
// under the KEK, and returns the public recipient (commit to repo) plus the
// wrapped bundle entry (add to the seald-root bundle). The plaintext private key
// is never returned — only its KEK-wrapped form.
func AddRepoKey() (recipient string, entry BundleEntry, err error) {
	kp, err := crypto.GenerateRepoKey()
	if err != nil {
		return "", BundleEntry{}, err
	}
	kek, err := crypto.GenerateKEK()
	if err != nil {
		return "", BundleEntry{}, err
	}
	wrapped, err := crypto.WrapKey([]byte(kp.Identity), kek)
	if err != nil {
		return "", BundleEntry{}, err
	}
	return kp.Recipient, BundleEntry{
		WrappedKeyB64: base64.StdEncoding.EncodeToString(wrapped),
		KEKB64:        base64.StdEncoding.EncodeToString(kek),
	}, nil
}

func b64decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
