package crypto

import (
	"bytes"
	"fmt"

	"filippo.io/age"
)

// stanzaLinePrefix is the exact byte prefix of a recipient-stanza opening line
// in the age v1 header. age's own header marshaller (internal/format) writes
// each stanza as "->" + " " + <Type> + ...  (see format.Stanza.Marshal), so a
// recipient stanza line always begins with "-> ". A wrapped-body line is
// RawStdEncoding base64 (A–Za–z0–9+/ only) and thus can never start with '-';
// the footer is "--- <mac>" which starts with "---", not "-> ". So counting
// lines that begin with "-> " over the canonical header is unambiguous.
var stanzaLinePrefix = []byte("-> ")

// RecipientStanzaCount parses an age v1 ciphertext header WITHOUT decrypting and
// returns the number of recipient stanzas (one per recipient). It errors if the
// input is not a well-formed age file.
//
// Per lessons.md L1, an age X25519 stanza carries only an ephemeral public share
// and the wrapped file key — NOT the recipient's long-term age1… public key. So
// the recipient a stanza was sealed to cannot be recovered from the blob. The
// realizable decrypt-free signal is therefore the stanza COUNT (how many
// recipients the file was sealed to), which is exactly what this returns. For
// the materializer's per-cluster isolation, a correctly-sealed entry has
// count == 2 (human + exactly one cluster); any other count is a violation
// (see client.VerifyBundle).
//
// Robustness: rather than hand-roll the age header grammar, this delegates
// framing validation to age.ExtractHeader, which runs age's own format.Parse
// (rejecting non-age input, truncated headers, malformed stanzas, a missing/
// short MAC, etc.) and returns the canonical re-marshalled header bytes. The
// count is then a trivial, unambiguous scan for "-> " line prefixes over those
// canonical bytes — no bespoke parser to drift from age's format.
func RecipientStanzaCount(ciphertext []byte) (int, error) {
	header, err := age.ExtractHeader(bytes.NewReader(ciphertext))
	if err != nil {
		return 0, fmt.Errorf("parse age header: %w", err)
	}
	count := 0
	for _, line := range bytes.Split(header, []byte("\n")) {
		if bytes.HasPrefix(line, stanzaLinePrefix) {
			count++
		}
	}
	if count < 1 {
		// A valid age header always has at least one recipient stanza; zero means
		// ExtractHeader returned something we didn't expect (defensive).
		return 0, fmt.Errorf("no recipient stanzas found in age header")
	}
	return count, nil
}

// NOTE on a decrypt-free per-identity "can this identity unwrap ITS stanza?"
// check (evaluated per plan Task 3.1, deliberately NOT added here):
//
// age.DecryptHeader(header, identity) unwraps a matching stanza's file key
// without opening the AEAD payload — a genuinely AEAD-open-free check. But it is
// redundant for gitseal's verify path: client.VerifyBundle proves the human
// stanza is usable by running a full crypto.UnsealVerified with the human
// identity, which additionally re-asserts the embedded project_id (strictly
// stronger than a bare header unwrap). Adding a second, weaker unwrap primitive
// here would duplicate that guarantee for no gain, so it is intentionally
// omitted. The stanza COUNT above is the only decrypt-free signal this file
// needs to expose.
