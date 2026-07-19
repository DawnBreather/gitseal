package crypto

import (
	"bytes"
	"testing"

	"filippo.io/age"
)

// sealRawEnvelopeForTest age-encrypts an arbitrary envelope string to recipient,
// bypassing SealWithLevel's validation — used to forge malicious blobs.
func sealRawEnvelopeForTest(t *testing.T, recipient, envelope string) []byte {
	t.Helper()
	rcpt, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, rcpt)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte(envelope))
	w.Close()
	return out.Bytes()
}

// AUDIT v2 #1 (high): a crafted blob embedding a below-default access level
// (0 or negative) must be rejected on unseal, not silently treated as "no
// elevated requirement". Only levels >= DefaultMinAccessLevel are trustworthy.
func TestUnsealVerifiedRejectsBelowDefaultLevel(t *testing.T) {
	kp, _ := GenerateRepoKey()
	// Forge a blob with an embedded level of 0 by sealing a hand-built envelope.
	// We can't use SealWithLevel (it rejects <=0), so craft via a raw helper.
	ct := sealRawEnvelopeForTest(t, kp.Recipient, "gitseal-project-id:412\ngitseal-min-access-level:0\n\nsecret")
	if _, _, err := UnsealVerified(ct, []byte(kp.Identity), 412); err == nil {
		t.Fatal("a below-default embedded level must be rejected")
	}
}

func TestUnsealVerifiedRejectsNegativeLevel(t *testing.T) {
	kp, _ := GenerateRepoKey()
	ct := sealRawEnvelopeForTest(t, kp.Recipient, "gitseal-project-id:412\ngitseal-min-access-level:-5\n\nsecret")
	if _, _, err := UnsealVerified(ct, []byte(kp.Identity), 412); err == nil {
		t.Fatal("a negative embedded level must be rejected")
	}
}
