package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"filippo.io/age"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// KeyFile schema versions.
//
//	v1: {wrapped_key_b64, kek_b64} — the age identity KEK-wrapped (legacy; the KEK
//	    shipped alongside so it gave no at-rest protection). Still parsed during the
//	    migration window.
//	v2: {private_key_b64} — the age identity stored DIRECTLY. The
//	    keystore now lives in a broker-owned, out-of-band Secret (never git), so the
//	    dead KEK indirection is removed. This is the current form.
const (
	KeyFileVersionV1 = "v1"
	KeyFileVersionV2 = "v2"
	// KeyFileVersion is the version `admin onboard` writes now.
	KeyFileVersion = KeyFileVersionV2
)

// keyFileSuffix is the extension the broker's directory loader globs for.
const keyFileSuffix = ".key.json"

// KeyFile is ONE repo's age identity, self-describing (version + project_id). The
// broker reads a DIRECTORY of these (<project_id>.key.json), so a single malformed
// file can no longer abort the whole fleet (the SPOF kill). The private key is only
// ever present here inside the broker's own out-of-band keystore Secret — NEVER in
// git. Either shape (v1 wrapped, v2 raw) resolves to the same identity via Identity().
type KeyFile struct {
	Version   string `json:"version"`
	ProjectID int64  `json:"project_id"`
	// v2 (current): the raw age identity ("AGE-SECRET-KEY-1…"), base64.
	PrivateKeyB64 string `json:"private_key_b64,omitempty"`
	// v1 (legacy, migration window): KEK-wrapped identity + its KEK, base64.
	WrappedKeyB64 string `json:"wrapped_key_b64,omitempty"`
	KEKB64        string `json:"kek_b64,omitempty"`
}

// NewKeyFileV2 builds the current (v2) key file: the raw age identity, base64. No KEK.
func NewKeyFileV2(projectID int64, identity string) *KeyFile {
	return &KeyFile{
		Version:       KeyFileVersionV2,
		ProjectID:     projectID,
		PrivateKeyB64: base64.StdEncoding.EncodeToString([]byte(identity)),
	}
}

// NewKeyFile builds a v1 (KEK-wrapped) key file. Retained for the migration window
// + tests; onboarding now emits v2 via NewKeyFileV2.
func NewKeyFile(projectID int64, wrapped, kek []byte) *KeyFile {
	return &KeyFile{
		Version:       KeyFileVersionV1,
		ProjectID:     projectID,
		WrappedKeyB64: base64.StdEncoding.EncodeToString(wrapped),
		KEKB64:        base64.StdEncoding.EncodeToString(kek),
	}
}

// KeyFileName is the on-disk name for a project's key file: "<project_id>.key.json".
func KeyFileName(projectID int64) string {
	return strconv.FormatInt(projectID, 10) + keyFileSuffix
}

// ParseKeyFile parses + validates KeyFile bytes for v1 OR v2: project_id must be > 0,
// the version must be known, and the version's fields must decode AND yield a valid
// age identity. Fail closed on anything else.
func ParseKeyFile(data []byte) (*KeyFile, error) {
	var kf KeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("parse key file: %w", err)
	}
	if kf.ProjectID <= 0 {
		return nil, fmt.Errorf("key file missing/invalid project_id (%d)", kf.ProjectID)
	}
	switch kf.Version {
	case KeyFileVersionV2:
		if kf.PrivateKeyB64 == "" {
			return nil, fmt.Errorf("v2 key file missing private_key_b64")
		}
	case KeyFileVersionV1:
		if kf.WrappedKeyB64 == "" || kf.KEKB64 == "" {
			return nil, fmt.Errorf("v1 key file missing wrapped_key_b64/kek_b64")
		}
	default:
		return nil, fmt.Errorf("unsupported key file version %q (want v1 or v2)", kf.Version)
	}
	// Resolve + validate the identity now, so a bad key is caught at parse time
	// (fail closed) rather than at unseal.
	if _, err := kf.Identity(); err != nil {
		return nil, fmt.Errorf("key file %d: %w", kf.ProjectID, err)
	}
	return &kf, nil
}

// Identity resolves the key file to the raw age identity string ("AGE-SECRET-KEY-1…"),
// unwrapping a v1 KEK envelope or base64-decoding a v2 raw key. It validates the
// result parses as an age X25519 identity. This is the single accessor the broker +
// verify use — neither cares which on-disk shape produced it.
func (kf *KeyFile) Identity() (string, error) {
	var identity string
	switch kf.Version {
	case KeyFileVersionV2:
		raw, err := base64.StdEncoding.DecodeString(kf.PrivateKeyB64)
		if err != nil {
			return "", fmt.Errorf("private_key_b64: %w", err)
		}
		identity = string(raw)
	case KeyFileVersionV1:
		wrapped, err := base64.StdEncoding.DecodeString(kf.WrappedKeyB64)
		if err != nil {
			return "", fmt.Errorf("wrapped_key_b64: %w", err)
		}
		kek, err := base64.StdEncoding.DecodeString(kf.KEKB64)
		if err != nil {
			return "", fmt.Errorf("kek_b64: %w", err)
		}
		id, err := crypto.UnwrapKey(wrapped, kek)
		if err != nil {
			return "", fmt.Errorf("unwrap: %w", err)
		}
		identity = string(id)
	default:
		return "", fmt.Errorf("unsupported version %q", kf.Version)
	}
	if _, err := age.ParseX25519Identity(identity); err != nil {
		return "", fmt.Errorf("not a valid age identity: %w", err)
	}
	return identity, nil
}

// Verify confirms the key file resolves to an identity whose public recipient equals
// expectedRecipient — the offline check behind `verify-keys` + `admin onboard`'s
// self-check (a malformed / recipient-mismatched key is caught before the broker).
func (kf *KeyFile) Verify(expectedRecipient string) error {
	identity, err := kf.Identity()
	if err != nil {
		return err
	}
	id, err := age.ParseX25519Identity(identity)
	if err != nil {
		return fmt.Errorf("not a valid age identity: %w", err)
	}
	if got := id.Recipient().String(); got != expectedRecipient {
		return fmt.Errorf("recipient mismatch: key derives %s, expected %s", got, expectedRecipient)
	}
	return nil
}

// KeyStore holds per-repo age identities keyed by project id — the resolved form the
// broker's unseal path consumes (it passes the identity straight to
// crypto.UnsealVerified; no KEK step). Lives with the file format it loads.
type KeyStore struct {
	Identities map[int64]string // project_id -> "AGE-SECRET-KEY-1…"
}

// LoadKeyDir reads every "<pid>.key.json" in dir into a KeyStore, resolving each to
// its age identity (v1 or v2). TOLERANT: a file that fails to parse/validate is
// SKIPPED (appended to `skipped`) rather than aborting — one bad key downs only its
// own repo, never the fleet. Fatal ONLY if dir is unreadable or ZERO valid keys are
// found (an empty keystore is a loud failure, not a silent-healthy one). Non-
// ".key.json" files are ignored.
func LoadKeyDir(dir string) (ks *KeyStore, skipped []string, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("read keystore dir %s: %w", dir, err)
	}
	ks = &KeyStore{Identities: map[int64]string{}}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), keyFileSuffix) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // deterministic skip ordering
	for _, name := range names {
		data, rerr := os.ReadFile(filepath.Join(dir, name))
		if rerr != nil {
			skipped = append(skipped, fmt.Sprintf("%s: read: %v", name, rerr))
			continue
		}
		kf, perr := ParseKeyFile(data)
		if perr != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", name, perr))
			continue
		}
		identity, ierr := kf.Identity() // validated in ParseKeyFile, but resolve for the map
		if ierr != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", name, ierr))
			continue
		}
		ks.Identities[kf.ProjectID] = identity
	}
	if len(ks.Identities) == 0 {
		return nil, skipped, fmt.Errorf("no valid key files in %s (%d skipped) — keystore is empty", dir, len(skipped))
	}
	return ks, skipped, nil
}
