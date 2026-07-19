package client

import (
	"fmt"

	"golang.org/x/crypto/ssh"
)

// SignerResolver resolves a signer fingerprint to its registered SSH public key
// and the signer's LIVE project access level. Backed by the broker's user registry
// + a live GitLab members/all check (the snapshot for the pubkey, live for level).
// Kept as an interface so the verdict is a pure, testable function.
type SignerResolver interface {
	// PubKeyFor returns the registered public key for a fingerprint (ok=false if
	// the fingerprint is not a registered user — fail closed).
	PubKeyFor(fingerprint string) (ssh.PublicKey, bool)
	// LiveLevelFor returns the signer's current effective project access level
	// (0 if not a member). An error means "couldn't determine" → caller fails closed.
	LiveLevelFor(fingerprint string) (int, error)
}

// VerifySectionAuthz is the signature-enforced write-authz check for ONE changed
// env section (Stage B). It FAILS CLOSED unless ALL hold:
//
//  1. the section carries a signature (missing → deny);
//  2. the signer fingerprint is a REGISTERED user (unknown → deny);
//  3. the signature verifies against that registered pubkey over the section's
//     CANONICAL bytes (tamper/spoof → deny);
//  4. the signer's LIVE project level >= minLevel for this env (under-level → deny).
//
// This folds the write-authz into attribution: the signer's live level IS
// the authorization, and every sealed change is provably attributed to a currently-
// authorized human. project_id binds the canonical bytes (a section can't be lifted
// to another repo).
func VerifySectionAuthz(projectID int64, env string, sec EnvSection, minLevel int, r SignerResolver) error {
	return verifySectionAuthz(CanonicalSectionBytes(projectID, env, sec.Entries), env, sec, minLevel, r)
}

// VerifySectionAuthzV4 is the v4 signature-enforced write-authz check:
// identical to VerifySectionAuthz but the canonical bytes bind to the project
// PUBKEY (a v4 repo has no numeric id). Same fail-closed rules.
func VerifySectionAuthzV4(pubkey, env string, sec EnvSection, minLevel int, r SignerResolver) error {
	return verifySectionAuthz(CanonicalSectionBytesV4(pubkey, env, sec.Entries), env, sec, minLevel, r)
}

// verifySectionAuthz is the shared fail-closed core: given the section's canonical
// signed bytes (v3 numeric or v4 pubkey), enforce signature present + registered
// signer + signature verifies + live level >= minLevel.
func verifySectionAuthz(msg []byte, env string, sec EnvSection, minLevel int, r SignerResolver) error {
	if sec.Sig == nil || sec.Sig.Sig == "" || sec.Sig.By == "" {
		return fmt.Errorf("env %q: missing signature (every sealed section must be signed by a registered user)", env)
	}
	pub, ok := r.PubKeyFor(sec.Sig.By)
	if !ok {
		return fmt.Errorf("env %q: signer %s is not a registered gitseal user (fail closed)", env, sec.Sig.By)
	}
	if err := VerifySSHSig(pub, msg, sec.Sig.Sig); err != nil {
		return fmt.Errorf("env %q: signature does not verify for signer %s (tampered or spoofed): %w", env, sec.Sig.By, err)
	}
	lvl, err := r.LiveLevelFor(sec.Sig.By)
	if err != nil {
		return fmt.Errorf("env %q: could not resolve signer %s live level (fail closed): %w", env, sec.Sig.By, err)
	}
	if lvl < minLevel {
		return fmt.Errorf("env %q: signer %s has live level %d, needs %d to change this env's secrets", env, sec.Sig.By, lvl, minLevel)
	}
	return nil
}
