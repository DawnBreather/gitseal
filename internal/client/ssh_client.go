package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"net"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// SSHSigner is the minimal signing capability the SSH-auth unseal needs: sign the
// challenge nonce + expose the public key (for the fingerprint header). Backed by
// the ssh-agent when available, else a decrypted on-disk private key.
type SSHSigner struct {
	signer ssh.Signer
}

// LoadSSHSigner resolves a signer: prefer the ssh-agent (SSH_AUTH_SOCK) matching
// the given public-key fingerprint (private key never leaves the agent); else load
// the private key file at keyPath (must be unencrypted, or use the agent). If
// wantFingerprint is "", the first agent key (or the keyPath key) is used.
func LoadSSHSigner(keyPath, wantFingerprint string) (*SSHSigner, error) {
	// 1) ssh-agent
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			ag := agent.NewClient(conn)
			if signers, err := ag.Signers(); err == nil {
				for _, s := range signers {
					if wantFingerprint == "" || ssh.FingerprintSHA256(s.PublicKey()) == wantFingerprint {
						return &SSHSigner{signer: s}, nil
					}
				}
			}
		}
	}
	// 2) on-disk key
	if keyPath != "" {
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read ssh key %s: %w", keyPath, err)
		}
		s, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse ssh key %s (encrypted keys need the agent): %w", keyPath, err)
		}
		if wantFingerprint != "" && ssh.FingerprintSHA256(s.PublicKey()) != wantFingerprint {
			return nil, fmt.Errorf("ssh key %s fingerprint != requested %s", keyPath, wantFingerprint)
		}
		return &SSHSigner{signer: s}, nil
	}
	return nil, fmt.Errorf("no ssh signer (set SSH_AUTH_SOCK or pass a key path)")
}

// NewSSHSignerFrom wraps an existing ssh.Signer (used by tests + any caller that
// already holds a signer, e.g. from an agent).
func NewSSHSignerFrom(s ssh.Signer) *SSHSigner { return &SSHSigner{signer: s} }

// Fingerprint returns the signer's public-key SHA256 fingerprint.
func (s *SSHSigner) Fingerprint() string { return ssh.FingerprintSHA256(s.signer.PublicKey()) }

// PublicKeyLine returns the "ssh-ed25519 AAAA…" authorized-key line (for onboarding).
func (s *SSHSigner) PublicKeyLine() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.signer.PublicKey())))
}

// Sign signs msg, returning the base64 marshaled ssh.Signature (VerifySSHSig-compatible).
func (s *SSHSigner) Sign(msg []byte) (string, error) { return SignSSHSig(s.signer, msg) }

// UnsealSSH performs the SSH challenge-response unseal (Stage D): fetch a
// nonce from the broker, SSH-sign it, and POST the unseal with the SSH auth
// headers. No PAT. The broker resolves the fingerprint→user_id and does the LIVE
// membership check (identical gate to PAT auth).
func UnsealSSH(brokerURL string, signer *SSHSigner, target UnsealTarget, name string, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("%s: empty ciphertext (nothing to unseal — check the secret name/env)", name)
	}
	base := strings.TrimRight(brokerURL, "/")
	hc := &http.Client{Timeout: 15 * time.Second}

	// 1) challenge
	cr, err := hc.Post(base+"/v1/challenge", "application/json", nil)
	if err != nil {
		return nil, fmt.Errorf("broker challenge unreachable: %w", err)
	}
	defer cr.Body.Close()
	if cr.StatusCode != 200 {
		return nil, fmt.Errorf("broker challenge failed (%d)", cr.StatusCode)
	}
	var ch struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(cr.Body).Decode(&ch); err != nil || ch.Nonce == "" {
		return nil, fmt.Errorf("bad challenge response")
	}

	// 2) sign the nonce
	sig, err := signer.Sign([]byte(ch.Nonce))
	if err != nil {
		return nil, fmt.Errorf("sign challenge: %w", err)
	}

	// 3) unseal with SSH auth headers
	body := unsealBody(target, name, ciphertext)
	req, _ := http.NewRequest("POST", base+"/v1/unseal", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Seald-Fingerprint", signer.Fingerprint())
	req.Header.Set("X-Seald-Nonce", ch.Nonce)
	req.Header.Set("X-Seald-Signature", sig)
	if id := os.Getenv("SEALD_CF_CLIENT_ID"); id != "" {
		req.Header.Set("CF-Access-Client-Id", id)
		req.Header.Set("CF-Access-Client-Secret", os.Getenv("SEALD_CF_CLIENT_SECRET"))
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("broker unreachable: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("broker denied (%d): %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var out struct {
		PlaintextB64 string `json:"plaintext_b64"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return nil, fmt.Errorf("bad broker response: %w", err)
	}
	return base64.StdEncoding.DecodeString(out.PlaintextB64)
}
