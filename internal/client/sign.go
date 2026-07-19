package client

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"sort"

	"golang.org/x/crypto/ssh"
)

// --- per-env-section attribution signatures (Stage B) ----------------
//
// A signature attests WHO sealed an env section. It signs the section's CANONICAL
// bytes (stable regardless of map order) with the user's SSH key. The user key is
// used for identity/signature ONLY — NEVER as an encryption recipient (invariant
// #6). Verify is pure Go (x/crypto/ssh) so the enforcement gate needs no
// ssh-keygen; the client sign path may use `ssh-keygen -Y sign` (agent-compatible)
// OR an in-process ssh.Signer — both produce a signature VerifySSHSig accepts,
// because the wire format here is the ssh.Signature marshaling, not SSHSIG.

// CanonicalSectionBytes returns a stable byte serialization of an env section:
// project_id ‖ env ‖ sorted (key, ciphertext) pairs, each length-prefixed so no
// concatenation ambiguity. Order-independent (keys sorted) and tamper-evident
// (any key/ct/env/project change alters the output). This is what gets signed.
func CanonicalSectionBytes(projectID int64, env string, entries map[string]string) []byte {
	var buf []byte
	putU64 := func(n uint64) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], n)
		buf = append(buf, b[:]...)
	}
	putStr := func(s string) {
		putU64(uint64(len(s)))
		buf = append(buf, s...)
	}
	buf = append(buf, "gitseal-section-v1\x00"...)
	putU64(uint64(projectID))
	putStr(env)
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	putU64(uint64(len(keys)))
	for _, k := range keys {
		putStr(k)
		putStr(entries[k])
	}
	// hash the framing so the signed payload is a fixed 32 bytes (SSH signs the
	// message directly; hashing keeps large sections cheap + uniform).
	sum := sha256.Sum256(buf)
	return sum[:]
}

// CanonicalSectionBytesV4 is the v4 section serialization: it binds to
// the project PUBKEY instead of the numeric project_id (a v4 repo carries no
// numeric id). Domain tag "gitseal-section-v2\x00" separates it from v3 so a v3
// signature can never be replayed as a v4 one (and vice-versa). Same length-prefix
// framing + sha256 → fixed 32-byte signed payload.
func CanonicalSectionBytesV4(pubkey, env string, entries map[string]string) []byte {
	var buf []byte
	putU64 := func(n uint64) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], n)
		buf = append(buf, b[:]...)
	}
	putStr := func(s string) {
		putU64(uint64(len(s)))
		buf = append(buf, s...)
	}
	buf = append(buf, "gitseal-section-v2\x00"...)
	putStr(pubkey)
	putStr(env)
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	putU64(uint64(len(keys)))
	for _, k := range keys {
		putStr(k)
		putStr(entries[k])
	}
	sum := sha256.Sum256(buf)
	return sum[:]
}

// SignSSHSig signs msg with an in-process ssh.Signer and returns the base64 of the
// marshaled ssh.Signature. (Client CLIs that prefer the agent use `ssh-keygen -Y
// sign`; a small adapter converts that to the same marshaled form — both verify.)
func SignSSHSig(signer ssh.Signer, msg []byte) (string, error) {
	sig, err := signer.Sign(rand.Reader, msg)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ssh.Marshal(sig)), nil
}

// VerifySSHSig verifies a base64 marshaled ssh.Signature over msg against pub.
// Pure Go — no ssh-keygen. Returns nil iff the signature is valid for this key +
// message (fail-closed on any parse/verify error).
func VerifySSHSig(pub ssh.PublicKey, msg []byte, sigB64 string) error {
	raw, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("signature base64: %w", err)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(raw, &sig); err != nil {
		return fmt.Errorf("signature unmarshal: %w", err)
	}
	if err := pub.Verify(msg, &sig); err != nil {
		return fmt.Errorf("signature verify: %w", err)
	}
	return nil
}

// KeyFingerprint returns the SHA256 fingerprint ("SHA256:…") of an SSH public key
// — the stable identifier stored as EnvSectionSig.By and keyed in the user registry.
func KeyFingerprint(pub ssh.PublicKey) string {
	return ssh.FingerprintSHA256(pub)
}

// ParseAuthorizedKey parses one "ssh-ed25519 AAAA… comment" line into a public key.
func ParseAuthorizedKey(line string) (ssh.PublicKey, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("parse ssh public key: %w", err)
	}
	return pub, nil
}

// AuthorizedKeyLine returns the canonical "ssh-ed25519 AAAA…" line for a key.
func AuthorizedKeyLine(pub ssh.PublicKey) string {
	return string(ssh.MarshalAuthorizedKey(pub))[:len(ssh.MarshalAuthorizedKey(pub))-1] // trim trailing \n
}

// FingerprintOfLine parses an authorized-key line and returns its SHA256 fingerprint.
func FingerprintOfLine(line string) (string, error) {
	pub, err := ParseAuthorizedKey(line)
	if err != nil {
		return "", err
	}
	return KeyFingerprint(pub), nil
}

// KeyLineFingerprintMatch reports whether an authorized-key line has the given
// SHA256 fingerprint (used to check a key on a GitLab profile matches).
func KeyLineFingerprintMatch(line, fingerprint string) bool {
	fp, err := FingerprintOfLine(line)
	return err == nil && fp == fingerprint
}
