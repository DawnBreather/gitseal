package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
)

// --- per-env-section canonical bytes + SSHSIG verify (Stage B) --------
//
// Attribution signs the CANONICAL bytes of an env section (stable across map
// iteration order) with the user's SSH key. We verify with a pure-Go SSHSIG
// verifier (no ssh-keygen dependency in the broker/CI verify path). The client
// SIGN side may use `ssh-keygen -Y sign` (agent-compatible); this test exercises
// the verify + canonicalization that the enforcement gate relies on.

func TestCanonicalSectionBytes_StableAndBinding(t *testing.T) {
	// same logical section, different map insertion order → identical canonical bytes
	a := CanonicalSectionBytes(338, "prod", map[string]string{"B": "ctB", "A": "ctA"})
	b := CanonicalSectionBytes(338, "prod", map[string]string{"A": "ctA", "B": "ctB"})
	if string(a) != string(b) {
		t.Fatal("canonical bytes must be order-independent")
	}
	// binding: env, project, and each (key,ct) all change the bytes
	if string(a) == string(CanonicalSectionBytes(338, "staging", map[string]string{"A": "ctA", "B": "ctB"})) {
		t.Error("env must bind")
	}
	if string(a) == string(CanonicalSectionBytes(999, "prod", map[string]string{"A": "ctA", "B": "ctB"})) {
		t.Error("project_id must bind")
	}
	if string(a) == string(CanonicalSectionBytes(338, "prod", map[string]string{"A": "ctA-TAMPERED", "B": "ctB"})) {
		t.Error("a ciphertext change must break the canonical bytes (tamper-evident)")
	}
}

// A real SSHSIG (produced here with ssh.SignWithAlgorithm over the wire format via
// the SSHSIG helper we implement) verifies against the signer's public key, and
// FAILS on a tampered message or a different key.
func TestVerifySSHSig(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("canonical-section-bytes")

	sig, err := SignSSHSig(signer, msg)
	if err != nil {
		t.Fatalf("SignSSHSig: %v", err)
	}
	// verifies against the right key + message
	if err := VerifySSHSig(sshPub, msg, sig); err != nil {
		t.Fatalf("VerifySSHSig should pass: %v", err)
	}
	// tampered message → fail
	if err := VerifySSHSig(sshPub, []byte("tampered"), sig); err == nil {
		t.Fatal("VerifySSHSig must fail on a tampered message")
	}
	// different key → fail
	otherPubRaw, _, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _ := ssh.NewPublicKey(otherPubRaw)
	if err := VerifySSHSig(otherPub, msg, sig); err == nil {
		t.Fatal("VerifySSHSig must fail against a different key")
	}
}

// Fingerprint of a public key is stable + matches ssh.FingerprintSHA256.
func TestKeyFingerprint(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	fp := KeyFingerprint(sshPub)
	if fp == "" || fp != ssh.FingerprintSHA256(sshPub) {
		t.Fatalf("fingerprint mismatch: %q", fp)
	}
}
