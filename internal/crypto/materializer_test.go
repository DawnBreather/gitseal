package crypto

import (
	"bytes"
	"strings"
	"testing"
)

// --- Task 1.1 [SECURITY, THE CRUX]: per-cluster multi-recipient isolation ------
//
// SealMulti seals a value to EXACTLY the given set of recipients. The security
// invariant is that a keyholder NOT in that set can never decrypt the blob —
// this is what enforces per-cluster isolation once the materializer seals each
// env to only its cluster's recipient (plus the human recipient).

// TestSealMultiPerClusterIsolation seals a prod/preprod value to [human, G] and
// asserts that the staging key (S) and an unrelated stranger both FAIL to open
// it, while human and G succeed and recover the exact body + level.
func TestSealMultiPerClusterIsolation(t *testing.T) {
	human, err := GenerateRepoKey()
	if err != nil {
		t.Fatalf("GenerateRepoKey(human): %v", err)
	}
	g, err := GenerateRepoKey() // example (prod + preprod) cluster key
	if err != nil {
		t.Fatalf("GenerateRepoKey(g): %v", err)
	}
	s, err := GenerateRepoKey() // staging cluster key
	if err != nil {
		t.Fatalf("GenerateRepoKey(s): %v", err)
	}
	stranger, err := GenerateRepoKey() // unrelated keyholder
	if err != nil {
		t.Fatalf("GenerateRepoKey(stranger): %v", err)
	}

	plaintext := []byte("postgres.example.internal")
	const projectID int64 = 338

	ct, err := SealMulti(plaintext, []string{human.Recipient, g.Recipient}, projectID, "DB_HOST", DefaultMinAccessLevel)
	if err != nil {
		t.Fatalf("SealMulti: %v", err)
	}
	if bytes.Contains(ct, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}

	cases := []struct {
		name     string
		identity string
		wantOK   bool
	}{
		{"human", human.Identity, true},
		{"g", g.Identity, true},
		{"s", s.Identity, false},
		{"stranger", stranger.Identity, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, level, err := UnsealVerified(ct, []byte(tc.identity), projectID)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("%s: expected success, got error: %v", tc.name, err)
				}
				if !bytes.Equal(body, plaintext) {
					t.Fatalf("%s: body mismatch: got %q want %q", tc.name, body, plaintext)
				}
				if level != DefaultMinAccessLevel {
					t.Fatalf("%s: level mismatch: got %d want %d", tc.name, level, DefaultMinAccessLevel)
				}
				return
			}
			// FAIL case: a non-recipient MUST NOT decrypt. If it does, that is
			// a per-cluster isolation breach — the whole point of SealMulti.
			if err == nil {
				t.Fatalf("SECURITY FAILURE: non-recipient %s decrypted a blob it was not sealed to", tc.name)
			}
		})
	}
}

// TestSealMultiStagingIsolation is the mirror case: a staging value sealed to
// [human, S] must open for human and S but FAIL for the example key (G).
func TestSealMultiStagingIsolation(t *testing.T) {
	human, err := GenerateRepoKey()
	if err != nil {
		t.Fatalf("GenerateRepoKey(human): %v", err)
	}
	g, err := GenerateRepoKey()
	if err != nil {
		t.Fatalf("GenerateRepoKey(g): %v", err)
	}
	s, err := GenerateRepoKey()
	if err != nil {
		t.Fatalf("GenerateRepoKey(s): %v", err)
	}

	plaintext := []byte("staging-only-value")
	const projectID int64 = 338

	ct, err := SealMulti(plaintext, []string{human.Recipient, s.Recipient}, projectID, "DB_HOST", DefaultMinAccessLevel)
	if err != nil {
		t.Fatalf("SealMulti: %v", err)
	}

	cases := []struct {
		name     string
		identity string
		wantOK   bool
	}{
		{"human", human.Identity, true},
		{"s", s.Identity, true},
		{"g", g.Identity, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, level, err := UnsealVerified(ct, []byte(tc.identity), projectID)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("%s: expected success, got error: %v", tc.name, err)
				}
				if !bytes.Equal(body, plaintext) {
					t.Fatalf("%s: body mismatch: got %q want %q", tc.name, body, plaintext)
				}
				if level != DefaultMinAccessLevel {
					t.Fatalf("%s: level mismatch: got %d want %d", tc.name, level, DefaultMinAccessLevel)
				}
				return
			}
			if err == nil {
				t.Fatalf("SECURITY FAILURE: non-recipient %s decrypted a staging blob it was not sealed to", tc.name)
			}
		})
	}
}

// TestSealMultiWrongProjectRejected confirms the embedded project-id binding
// survives multi-recipient sealing: a blob sealed for project 100 must be
// rejected when unsealed against project 200 even by a legitimate recipient.
func TestSealMultiWrongProjectRejected(t *testing.T) {
	human, err := GenerateRepoKey()
	if err != nil {
		t.Fatalf("GenerateRepoKey(human): %v", err)
	}
	g, err := GenerateRepoKey()
	if err != nil {
		t.Fatalf("GenerateRepoKey(g): %v", err)
	}

	ct, err := SealMulti([]byte("secret"), []string{human.Recipient, g.Recipient}, 100, "X", DefaultMinAccessLevel)
	if err != nil {
		t.Fatalf("SealMulti: %v", err)
	}

	_, _, err = UnsealVerified(ct, []byte(g.Identity), 200)
	if err == nil {
		t.Fatal("expected project id mismatch rejection, got success")
	}
	if !strings.Contains(err.Error(), "project id mismatch") {
		t.Fatalf("expected 'project id mismatch' error, got: %v", err)
	}
}

// --- Task 1.2: single-recipient shim proves the refactor is byte-behaviorally
// identical to the pre-refactor SealWithLevel path. ----------------------------
func TestSealWithLevelSingleRecipientShim(t *testing.T) {
	kp, err := GenerateRepoKey()
	if err != nil {
		t.Fatalf("GenerateRepoKey: %v", err)
	}
	plaintext := []byte("single-recipient-value")
	const projectID int64 = 338
	const level = 40 // GitLab Maintainer, above the default

	ct, err := SealWithLevel(plaintext, kp.Recipient, projectID, "DATABASE_URL", level)
	if err != nil {
		t.Fatalf("SealWithLevel: %v", err)
	}
	if bytes.Contains(ct, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}

	body, gotLevel, err := UnsealVerified(ct, []byte(kp.Identity), projectID)
	if err != nil {
		t.Fatalf("UnsealVerified: %v", err)
	}
	if !bytes.Equal(body, plaintext) {
		t.Fatalf("body mismatch: got %q want %q", body, plaintext)
	}
	if gotLevel != level {
		t.Fatalf("level mismatch: got %d want %d", gotLevel, level)
	}
}

// --- Task 1.1 [SECURITY, fail-closed guards]: lock SealMulti's input validation
//
// SealMulti MUST reject bad input BEFORE any crypto and MUST return a nil
// ciphertext on rejection — never a partial or (worse) unencrypted body. These
// cases pin every guard so a future refactor that silently drops one is caught
// as a failing test rather than shipping as a fail-open regression.
func TestSealMultiValidation(t *testing.T) {
	// One valid recipient for the cases whose invalidity is NOT the recipient set.
	kp, err := GenerateRepoKey()
	if err != nil {
		t.Fatalf("GenerateRepoKey: %v", err)
	}
	valid := kp.Recipient

	cases := []struct {
		name       string
		recipients []string
		projectID  int64
		minLevel   int
		wantErrSub string // substring the error must mention
	}{
		{
			name:       "empty recipients",
			recipients: []string{},
			projectID:  338,
			minLevel:   30,
			wantErrSub: "at least one",
		},
		{
			name:       "nil recipients",
			recipients: nil,
			projectID:  338,
			minLevel:   30,
			wantErrSub: "recipient",
		},
		{
			name:       "garbage recipient",
			recipients: []string{"not-an-age-recipient"},
			projectID:  338,
			minLevel:   30,
			wantErrSub: "parse recipient",
		},
		{
			name:       "non-positive project id",
			recipients: []string{valid},
			projectID:  0,
			minLevel:   30,
			wantErrSub: "project id",
		},
		{
			name:       "non-positive min level",
			recipients: []string{valid},
			projectID:  338,
			minLevel:   0,
			wantErrSub: "min access level",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := SealMulti([]byte("x"), tc.recipients, tc.projectID, "N", tc.minLevel)
			// Fail closed: an error MUST be returned...
			if err == nil {
				t.Fatalf("expected error for %q, got nil (fail-open)", tc.name)
			}
			// ...and NO ciphertext may leak out alongside it.
			if ct != nil {
				t.Fatalf("expected nil ciphertext on rejection for %q, got %d bytes", tc.name, len(ct))
			}
			if tc.wantErrSub != "" && !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("error for %q = %q; want substring %q", tc.name, err.Error(), tc.wantErrSub)
			}
		})
	}
}
