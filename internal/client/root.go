package client

import (
	"encoding/base64"
	"fmt"

	"filippo.io/age"
	"github.com/hashicorp/vault/shamir"
)

// GenRoot generates the seald-root age keypair and Shamir-splits the PRIVATE key
// (the AGE-SECRET-KEY string) into n shares with threshold t. Returns the public
// recipient (for encrypting the bundle) and the base64-encoded shares. The
// plaintext private key is never returned — only its shares.
func GenRoot(n, t int) (recipient string, shares []string, err error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", nil, err
	}
	secret := []byte(id.String()) // "AGE-SECRET-KEY-1..."
	parts, err := shamir.Split(secret, n, t)
	if err != nil {
		return "", nil, fmt.Errorf("shamir split: %w", err)
	}
	shares = make([]string, len(parts))
	for i, p := range parts {
		shares[i] = base64.StdEncoding.EncodeToString(p)
	}
	return id.Recipient().String(), shares, nil
}

// CombineShares reconstructs the seald-root private key from >= threshold shares.
func CombineShares(shares []string) (string, error) {
	parts := make([][]byte, 0, len(shares))
	for _, s := range shares {
		p, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return "", fmt.Errorf("decode share: %w", err)
		}
		parts = append(parts, p)
	}
	secret, err := shamir.Combine(parts)
	if err != nil {
		return "", fmt.Errorf("shamir combine: %w", err)
	}
	return string(secret), nil
}
