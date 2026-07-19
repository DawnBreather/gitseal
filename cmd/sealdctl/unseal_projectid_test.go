package main

import (
	"testing"

	"github.com/dawnbreather/gitseal/internal/client"
)

// resolveUnsealProjectID reconciles a bundle's project_id with the repo's:
//   - v2 carries project_id in-file → it MUST match repo.yaml (defense-in-depth);
//   - v3 dropped project_id (== 0) → repo.yaml is authoritative (like materialize);
//   - a non-zero mismatch is always an error (wrong repo / tampered).
//
// This is what let the human unseal path work on v3 (it previously did a blind
// `bdl.ProjectID != rc.ProjectID`, which is 0 != 338 for every v3 bundle).
func TestResolveUnsealProjectID(t *testing.T) {
	cases := []struct {
		name     string
		bundleID int64
		repoID   int64
		want     int64
		wantErr  bool
	}{
		{"v2 match", 338, 338, 338, false},
		{"v2 mismatch", 338, 999, 0, true},
		{"v3 zero uses repo", 0, 338, 338, false},
		{"repo zero is invalid", 0, 0, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveUnsealProjectID(tc.bundleID, tc.repoID)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got id=%d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

// The v2 selector unseal must ACCEPT a v3 bundle (only v1 flat is rejected there).
func TestUnsealVersionAccepted(t *testing.T) {
	for _, v := range []string{client.BundleVersionV2, client.BundleVersionV3} {
		if err := checkUnsealBundleVersion(v); err != nil {
			t.Fatalf("version %q must be accepted by selector unseal: %v", v, err)
		}
	}
	if err := checkUnsealBundleVersion(client.BundleVersionV1); err == nil {
		t.Fatal("v1 flat must be rejected by the selector path")
	}
}
