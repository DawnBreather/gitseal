package client

import (
	"encoding/json"
	"fmt"
	"os"
)

// SignBundleFile signs each env section of the v3 bundle at path with the given
// SSH signer and writes the signatures back into the file (EnvSectionSig beside
// each section's entries). Attribution (Stage B): every section carries
// who sealed it. Only v3 is signed (v1/v2 are migration-read-only). projectID
// binds the canonical bytes. Returns the fingerprint that signed.
func SignBundleFile(path string, projectID int64, signer *SSHSigner) (string, error) {
	b, err := LoadBundle(path)
	if err != nil {
		return "", err
	}
	if b.Version != BundleVersionV3 {
		return "", fmt.Errorf("sign requires a v3 bundle; %s is %q", path, b.Version)
	}
	fp := signer.Fingerprint()
	for env, sec := range b.Envs {
		msg := CanonicalSectionBytes(projectID, env, sec.Entries)
		sig, err := signer.Sign(msg)
		if err != nil {
			return "", fmt.Errorf("sign env %q: %w", env, err)
		}
		sec.Sig = &EnvSectionSig{By: fp, Sig: sig}
		b.Envs[env] = sec
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
		return "", err
	}
	return fp, nil
}
