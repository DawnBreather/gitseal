package broker

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// bundleEntry is one repo's KEK-wrapped age identity + its KEK, base64-encoded,
// as stored in the (seald-root-decrypted) bundle file mounted into the broker.
type bundleEntry struct {
	WrappedKeyB64 string `json:"wrapped_key_b64"`
	KEKB64        string `json:"kek_b64"`
}

// LoadKeyStore reads the bundle JSON ({project_id: bundleEntry}) into a KeyStore.
func LoadKeyStore(path string) (*KeyStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	var raw map[string]bundleEntry
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}
	ks := &KeyStore{Identities: make(map[int64]string, len(raw))}
	for k, e := range raw {
		pid, err := strconv.ParseInt(k, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bundle: invalid project id %q: %w", k, err)
		}
		wrapped, err := base64.StdEncoding.DecodeString(e.WrappedKeyB64)
		if err != nil {
			return nil, fmt.Errorf("bundle: project %d wrapped key: %w", pid, err)
		}
		kek, err := base64.StdEncoding.DecodeString(e.KEKB64)
		if err != nil {
			return nil, fmt.Errorf("bundle: project %d kek: %w", pid, err)
		}
		// Unwrap to the raw identity now — the legacy monolith stored KEK-wrapped,
		// but the KeyStore holds resolved identities.
		id, err := crypto.UnwrapKey(wrapped, kek)
		if err != nil {
			return nil, fmt.Errorf("bundle: project %d unwrap: %w", pid, err)
		}
		ks.Identities[pid] = string(id)
	}
	return ks, nil
}
