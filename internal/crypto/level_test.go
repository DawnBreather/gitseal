package crypto

import "testing"

// v2: the required GitLab access level is embedded INSIDE the age AEAD envelope
// (like project_id), so the broker can enforce it and a cleartext-tampered
// bundle cannot downgrade it. SealWithLevel embeds it; UnsealVerified returns it.

func TestSealWithLevelRoundTripsLevel(t *testing.T) {
	kp, _ := GenerateRepoKey()
	ct, err := SealWithLevel([]byte("prod-secret"), kp.Recipient, 412, "DB", 40)
	if err != nil {
		t.Fatalf("SealWithLevel: %v", err)
	}
	pt, level, err := UnsealVerified(ct, []byte(kp.Identity), 412)
	if err != nil {
		t.Fatalf("UnsealVerified: %v", err)
	}
	if string(pt) != "prod-secret" {
		t.Fatalf("plaintext mismatch: %q", pt)
	}
	if level != 40 {
		t.Fatalf("embedded level: want 40, got %d", level)
	}
}

// Back-compat: a blob sealed with the old Seal() (no level header) must report
// the default level 30 (Developer), so existing sealed files keep working.
func TestUnsealVerifiedDefaultsLevel30WhenAbsent(t *testing.T) {
	kp, _ := GenerateRepoKey()
	ct, _ := Seal([]byte("legacy"), kp.Recipient, 412, "DB") // old API, no level
	pt, level, err := UnsealVerified(ct, []byte(kp.Identity), 412)
	if err != nil {
		t.Fatalf("UnsealVerified: %v", err)
	}
	if string(pt) != "legacy" || level != 30 {
		t.Fatalf("want legacy/30, got %q/%d", pt, level)
	}
}

// The embedded level is authoritative: it lives inside the AEAD, so it cannot be
// changed without the repo private key. (We can only assert it round-trips
// intact here; the downgrade *attack* — claiming a lower level at the broker —
// is exercised in the broker tests, where UnsealVerified surfaces the true 40.)
func TestUnsealVerifiedLevelSurvivesProjectIDCheck(t *testing.T) {
	kp, _ := GenerateRepoKey()
	ct, _ := SealWithLevel([]byte("x"), kp.Recipient, 412, "DB", 50)
	// wrong project id still rejected (existing R4), level irrelevant
	if _, _, err := UnsealVerified(ct, []byte(kp.Identity), 999); err == nil {
		t.Fatal("project id mismatch must still be rejected")
	}
	_, level, err := UnsealVerified(ct, []byte(kp.Identity), 412)
	if err != nil || level != 50 {
		t.Fatalf("want level 50, got %d (err %v)", level, err)
	}
}
