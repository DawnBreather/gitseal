// Package crypto implements gitseal's sealing primitives.
//
// A secret is sealed with age (X25519 + ChaCha20-Poly1305) to a per-repo public
// recipient, so sealing is fully offline — anyone who can clone the repo can seal,
// but only the holder of the repo's age identity (the broker) can unseal.
//
// The project_id is embedded as the first line of the age *plaintext* envelope
// and re-asserted on unseal. This binds a ciphertext to its repo cryptographically
// (independent of any operator-maintained key map), so a blob sealed for repo A
// cannot be decrypted "as" repo B even if the wrong key were somehow selected.
//
// Per-repo age private keys are themselves wrapped under a per-repo KEK
// (NaCl secretbox) so the broker only ever unwraps the single requested repo's
// key per request.
package crypto

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"

	"filippo.io/age"
	"golang.org/x/crypto/nacl/secretbox"
)

// RepoKey is a per-repo age keypair. Recipient is the public half (committed to
// the repo); Identity is the private half (held only by the broker, KEK-wrapped).
type RepoKey struct {
	Recipient string // age1...
	Identity  string // AGE-SECRET-KEY-1...
}

// GenerateRepoKey creates a fresh per-repo age keypair.
func GenerateRepoKey() (*RepoKey, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}
	return &RepoKey{
		Recipient: id.Recipient().String(),
		Identity:  id.String(),
	}, nil
}

const (
	envHeaderPrefix   = "gitseal-project-id:"
	levelHeaderPrefix = "gitseal-min-access-level:"
	// DefaultMinAccessLevel is assumed when a blob carries no level header
	// (legacy blobs sealed before v2). 30 = GitLab Developer.
	DefaultMinAccessLevel = 30
)

// Seal is the back-compat v1 entrypoint: seals at the default access level.
func Seal(plaintext []byte, recipient string, projectID int64, name string) ([]byte, error) {
	return SealWithLevel(plaintext, recipient, projectID, name, DefaultMinAccessLevel)
}

// SealWithLevel encrypts plaintext to the repo recipient, embedding projectID,
// name (advisory), and the REQUIRED GitLab access level — all INSIDE the age
// AEAD payload. The embedded level is authoritative: it cannot be changed
// without the repo private key, so a cleartext-tampered bundle cannot downgrade
// the access requirement (the broker re-asserts it after decrypt).
func SealWithLevel(plaintext []byte, recipient string, projectID int64, name string, minLevel int) ([]byte, error) {
	if projectID <= 0 {
		return nil, fmt.Errorf("invalid project id: must be positive, got %d", projectID)
	}
	if minLevel <= 0 {
		return nil, fmt.Errorf("invalid min access level: must be positive, got %d", minLevel)
	}
	rcpt, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return nil, fmt.Errorf("parse recipient: %w", err)
	}
	return sealEnvelope(plaintext, []age.Recipient{rcpt}, projectID, name, minLevel)
}

// SealMulti encrypts plaintext to a set of recipients, embedding the same
// project/level/name envelope header as SealWithLevel. The age payload is a
// single AEAD-protected body wrapped once per recipient, so any one of the
// recipients (and only those recipients) can decrypt it. This is the
// materializer's per-cluster isolation primitive: seal each env to
// [human, <that env's cluster key>] and no other keyholder can open it.
func SealMulti(plaintext []byte, recipients []string, projectID int64, name string, minLevel int) ([]byte, error) {
	// Guard order mirrors SealWithLevel (projectID → minLevel → recipients/parse)
	// so the two read as twins. All inputs are validated before any crypto.
	if projectID <= 0 {
		return nil, fmt.Errorf("invalid project id: must be positive, got %d", projectID)
	}
	if minLevel <= 0 {
		return nil, fmt.Errorf("invalid min access level: must be positive, got %d", minLevel)
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
	return sealEnvelope(plaintext, rcpts, projectID, name, minLevel)
}

// sealEnvelope builds the gitseal envelope header (project-id, min-access-level,
// name) followed by plaintext and age-encrypts it to all recipients. It is the
// single shared sealing core behind both SealWithLevel (one recipient) and
// SealMulti (many). With exactly one recipient it is byte-behaviorally identical
// to the pre-refactor SealWithLevel path.
func sealEnvelope(plaintext []byte, recipients []age.Recipient, projectID int64, name string, minLevel int) ([]byte, error) {
	var env bytes.Buffer
	fmt.Fprintf(&env, "%s%d\n", envHeaderPrefix, projectID)
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

// Unseal is the back-compat v1 entrypoint: returns only the plaintext.
func Unseal(ciphertext []byte, identity []byte, wantProjectID int64) ([]byte, error) {
	pt, _, err := UnsealVerified(ciphertext, identity, wantProjectID)
	return pt, err
}

// UnsealVerified decrypts an age blob with the repo identity, asserts the
// embedded project_id equals wantProjectID, and returns (plaintext, minLevel).
// minLevel is the access level embedded at seal time (DefaultMinAccessLevel if
// the blob predates v2). The identity []byte is zeroized before return.
func UnsealVerified(ciphertext []byte, identity []byte, wantProjectID int64) ([]byte, int, error) {
	defer zeroize(identity)
	header, body, err := decryptEnvelope(ciphertext, identity)
	if err != nil {
		return nil, 0, err
	}
	gotID, level, err := parseHeaders(header)
	if err != nil {
		return nil, 0, err
	}
	if gotID <= 0 {
		return nil, 0, fmt.Errorf("malformed envelope: missing or invalid project id header")
	}
	if gotID != wantProjectID {
		return nil, 0, fmt.Errorf("project id mismatch: ciphertext sealed for %d, requested %d", gotID, wantProjectID)
	}
	return body, level, nil
}

// EmbeddedProjectID decrypts a v1-v3 (numeric) envelope with identity and returns
// the project_id embedded in its header WITHOUT asserting it against an expected
// value — used by the v3→v4 migration, which must discover the embedded id (v3
// dropped it from the file) before it can re-assert-and-decrypt. The identity is
// NOT zeroized here (the caller decrypts again immediately after). Fails on a v4
// (pubkey) envelope, which carries no numeric id.
func EmbeddedProjectID(ciphertext []byte, identity []byte) (int64, error) {
	header, _, err := decryptEnvelope(ciphertext, identity)
	if err != nil {
		return 0, err
	}
	id, _, err := parseHeaders(header)
	if err != nil {
		return 0, err
	}
	if id <= 0 {
		return 0, fmt.Errorf("no numeric project id in envelope (v4 or malformed)")
	}
	return id, nil
}

// parseHeaders extracts the project id and (optional) min access level from the
// envelope header block. First occurrence of each wins (injected duplicates
// ignored). Missing level → DefaultMinAccessLevel.
func parseHeaders(header string) (projectID int64, level int, err error) {
	projectID = -1
	level = DefaultMinAccessLevel
	gotLevel := false
	gotID := false
	for _, line := range strings.Split(header, "\n") {
		switch {
		case !gotID && strings.HasPrefix(line, envHeaderPrefix):
			v := strings.TrimSpace(strings.TrimPrefix(line, envHeaderPrefix))
			projectID, err = strconv.ParseInt(v, 10, 64)
			if err != nil {
				return -1, 0, fmt.Errorf("parse embedded project id: %w", err)
			}
			gotID = true
		case !gotLevel && strings.HasPrefix(line, levelHeaderPrefix):
			lv, e := parseLevelLine(line)
			if e != nil {
				return -1, 0, e
			}
			level = lv
			gotLevel = true
		}
	}
	return projectID, level, nil
}

// parseLevelLine parses a "gitseal-min-access-level:<n>" line and enforces the
// AUDIT v2 #1 rule: a trustworthy embedded level is always >= the default
// (Developer). A blob claiming 0/negative/below-default is forged or corrupt —
// reject it rather than treat it as "no elevated requirement", which would let a
// crafted below-default blob skip the elevated re-check. Shared by the numeric
// (v1-v3) and pubkey (v4) header parsers.
func parseLevelLine(line string) (int, error) {
	v := strings.TrimSpace(strings.TrimPrefix(line, levelHeaderPrefix))
	lv, e := strconv.Atoi(v)
	if e != nil {
		return 0, fmt.Errorf("parse embedded min access level: %w", e)
	}
	if lv < DefaultMinAccessLevel {
		return 0, fmt.Errorf("embedded min access level %d below minimum %d", lv, DefaultMinAccessLevel)
	}
	return lv, nil
}

// --- KEK envelope (NaCl secretbox) -------------------------------------------

// GenerateKEK returns a fresh 32-byte key-encryption key.
func GenerateKEK() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// WrapKey encrypts secret under kek (24-byte random nonce prepended).
func WrapKey(secret, kek []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("kek must be 32 bytes, got %d", len(kek))
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	var key [32]byte
	copy(key[:], kek)
	out := secretbox.Seal(nonce[:], secret, &nonce, &key)
	return out, nil
}

// UnwrapKey reverses WrapKey.
func UnwrapKey(wrapped, kek []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("kek must be 32 bytes, got %d", len(kek))
	}
	if len(wrapped) < 24 {
		return nil, fmt.Errorf("wrapped key too short")
	}
	var nonce [24]byte
	copy(nonce[:], wrapped[:24])
	var key [32]byte
	copy(key[:], kek)
	out, ok := secretbox.Open(nil, wrapped[24:], &nonce, &key)
	if !ok {
		return nil, fmt.Errorf("unwrap failed: bad kek or corrupt data")
	}
	return out, nil
}
