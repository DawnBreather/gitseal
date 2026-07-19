package crypto

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
)

// v4 envelope: the embedded anti-splice discriminator is the project
// PUBLIC KEY (recipient) instead of the numeric project_id. This lets a repo's
// .seald/repo.yaml collapse to `recipient:` only — the pubkey is the sole project
// identity. The rest of the envelope (level header, name, body) is identical to
// v1-v3; only the discriminator header line differs, so a reader dispatches on
// which line is present.
//
//	v1-v3:  gitseal-project-id:<n>
//	v4:     gitseal-recipient:<age1…>
const recipientHeaderPrefix = "gitseal-recipient:"

// SealMultiV4 encrypts plaintext to a set of recipients, embedding the project's
// public key (ownerPubkey) as the anti-splice discriminator (v4). ownerPubkey is
// the repo's `recipient` — the identity every layer keys on. The recipients are
// the actual age recipients the body is wrapped to (e.g. [human, cluster-key]);
// ownerPubkey MAY or may not be among them (it is for the human path; for the
// materializer path the cluster key decrypts while ownerPubkey is the identity).
func SealMultiV4(plaintext []byte, recipients []string, ownerPubkey, name string, minLevel int) ([]byte, error) {
	if minLevel <= 0 {
		return nil, fmt.Errorf("invalid min access level: must be positive, got %d", minLevel)
	}
	if _, err := age.ParseX25519Recipient(ownerPubkey); err != nil {
		return nil, fmt.Errorf("parse owner pubkey: %w", err)
	}
	if len(recipients) < 1 {
		return nil, fmt.Errorf("invalid recipients: must have at least one, got %d", len(recipients))
	}
	rcpts := make([]age.Recipient, 0, len(recipients))
	for i, r := range recipients {
		rcpt, err := age.ParseX25519Recipient(r)
		if err != nil {
			return nil, fmt.Errorf("parse recipient %d: %w", i, err)
		}
		rcpts = append(rcpts, rcpt)
	}
	return sealEnvelopeV4(plaintext, rcpts, ownerPubkey, name, minLevel)
}

// sealEnvelopeV4 mirrors sealEnvelope but writes the recipient discriminator
// header instead of the numeric project-id header.
func sealEnvelopeV4(plaintext []byte, recipients []age.Recipient, ownerPubkey, name string, minLevel int) ([]byte, error) {
	var env bytes.Buffer
	fmt.Fprintf(&env, "%s%s\n", recipientHeaderPrefix, ownerPubkey)
	fmt.Fprintf(&env, "%s%d\n", levelHeaderPrefix, minLevel)
	fmt.Fprintf(&env, "gitseal-name:%s\n\n", name)
	env.Write(plaintext)

	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipients...)
	if err != nil {
		return nil, fmt.Errorf("age encrypt: %w", err)
	}
	if _, err := w.Write(env.Bytes()); err != nil {
		return nil, fmt.Errorf("write envelope: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("close age writer: %w", err)
	}
	return out.Bytes(), nil
}

// UnsealVerifiedByKey decrypts a v4 age blob with identity, asserts the embedded
// recipient (pubkey) equals wantPubkey, and returns (plaintext, minLevel). The
// identity []byte is zeroized before return. A v1-v3 (numeric) envelope has no
// recipient header and is rejected here (use UnsealVerified for those).
func UnsealVerifiedByKey(ciphertext []byte, identity []byte, wantPubkey string) ([]byte, int, error) {
	defer zeroize(identity)
	header, body, err := decryptEnvelope(ciphertext, identity)
	if err != nil {
		return nil, 0, err
	}
	gotPubkey, level, err := parseHeadersV4(header)
	if err != nil {
		return nil, 0, err
	}
	if gotPubkey == "" {
		return nil, 0, fmt.Errorf("not a v4 envelope: missing %s header", recipientHeaderPrefix)
	}
	if gotPubkey != wantPubkey {
		return nil, 0, fmt.Errorf("recipient (pubkey) mismatch: ciphertext sealed for %s, requested %s", gotPubkey, wantPubkey)
	}
	return body, level, nil
}

// decryptEnvelope is the shared decrypt-and-split core: age-decrypt with identity,
// then split the gitseal header block from the body at the blank-line separator.
func decryptEnvelope(ciphertext []byte, identity []byte) (header string, body []byte, err error) {
	id, err := age.ParseX25519Identity(string(identity))
	if err != nil {
		return "", nil, fmt.Errorf("parse identity: %w", err)
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), id)
	if err != nil {
		return "", nil, fmt.Errorf("age decrypt: %w", err)
	}
	env, err := io.ReadAll(r)
	if err != nil {
		return "", nil, fmt.Errorf("read envelope: %w", err)
	}
	sep := bytes.Index(env, []byte("\n\n"))
	if sep < 0 {
		return "", nil, fmt.Errorf("malformed envelope: no header separator")
	}
	return string(env[:sep]), env[sep+2:], nil
}

// parseHeadersV4 extracts the embedded recipient (pubkey) and min access level.
// First occurrence of each wins. Reuses the same level-validation rule as the
// numeric path (>= DefaultMinAccessLevel or reject).
func parseHeadersV4(header string) (pubkey string, level int, err error) {
	level = DefaultMinAccessLevel
	gotKey, gotLevel := false, false
	for _, line := range strings.Split(header, "\n") {
		switch {
		case !gotKey && strings.HasPrefix(line, recipientHeaderPrefix):
			pubkey = strings.TrimSpace(strings.TrimPrefix(line, recipientHeaderPrefix))
			if _, e := age.ParseX25519Recipient(pubkey); e != nil {
				return "", 0, fmt.Errorf("parse embedded recipient: %w", e)
			}
			gotKey = true
		case !gotLevel && strings.HasPrefix(line, levelHeaderPrefix):
			lv, e := parseLevelLine(line)
			if e != nil {
				return "", 0, e
			}
			level = lv
			gotLevel = true
		}
	}
	return pubkey, level, nil
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
