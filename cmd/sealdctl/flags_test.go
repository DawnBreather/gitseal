package main

import (
	"reflect"
	"testing"
)

// TestParseFlags covers the three flag forms plus the "--" terminator, and in
// particular the --key=value form that the in-cluster materializer hook relies on
// (`materialize --dir=/repo`). Before the fix, `--dir=/repo` was parsed as a bogus
// bool flag literally named "dir=/repo" and flags["dir"] resolved empty → the glob
// fell back to ./.sealed and "no bundles found".
func TestParseFlags(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantFlags map[string]string
		wantRest  []string
	}{
		{
			name:      "equals form: --dir=/x",
			args:      []string{"--dir=/x"},
			wantFlags: map[string]string{"dir": "/x"},
		},
		{
			name:      "space form: --dir /x",
			args:      []string{"--dir", "/x"},
			wantFlags: map[string]string{"dir": "/x"},
		},
		{
			// The real hook-adjacent combo: a bool flag, a space-form value flag,
			// and another space-form value flag. --dir must resolve to /x, NOT "".
			name:      "hook combo: --emit-yaml --dir /x --identity /dev/null",
			args:      []string{"--emit-yaml", "--dir", "/x", "--identity", "/dev/null"},
			wantFlags: map[string]string{"emit-yaml": "true", "dir": "/x", "identity": "/dev/null"},
		},
		{
			// Same combo but --dir given in equals form (what the k8s Job passes).
			name:      "hook combo with --dir=/x",
			args:      []string{"--emit-yaml", "--dir=/x", "--identity=/dev/null"},
			wantFlags: map[string]string{"emit-yaml": "true", "dir": "/x", "identity": "/dev/null"},
		},
		{
			name:      "value containing '=' splits on first '='",
			args:      []string{"--kv=a=b=c"},
			wantFlags: map[string]string{"kv": "a=b=c"},
		},
		{
			name:      "empty value: --key= yields empty string (not bool true)",
			args:      []string{"--key="},
			wantFlags: map[string]string{"key": ""},
		},
		{
			name:      "bare bool flag at end",
			args:      []string{"--stdin"},
			wantFlags: map[string]string{"stdin": "true"},
		},
		{
			name:      "bool flag followed by another flag",
			args:      []string{"--strict", "--name", "X"},
			wantFlags: map[string]string{"strict": "true", "name": "X"},
		},
		{
			// Existing space-form callers (seal --name X --value Y) must still work.
			name:      "seal space form: --name X --value Y",
			args:      []string{"--name", "X", "--value", "Y"},
			wantFlags: map[string]string{"name": "X", "value": "Y"},
		},
		{
			name:      "unseal space form: --name Z",
			args:      []string{"--name", "Z"},
			wantFlags: map[string]string{"name": "Z"},
		},
		{
			name:      "last wins on repeated flag",
			args:      []string{"--name", "A", "--name=B"},
			wantFlags: map[string]string{"name": "B"},
		},
		{
			// "--" terminator: everything after is rest (inject mode).
			name:      "double-dash terminator captures rest",
			args:      []string{"--name", "X", "--", "env", "sh", "-c", "echo hi"},
			wantFlags: map[string]string{"name": "X"},
			wantRest:  []string{"env", "sh", "-c", "echo hi"},
		},
		{
			name:      "no flags",
			args:      []string{},
			wantFlags: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags, rest := parseFlags(tt.args)
			if !reflect.DeepEqual(flags, tt.wantFlags) {
				t.Errorf("flags = %v, want %v", flags, tt.wantFlags)
			}
			if len(rest) != 0 || len(tt.wantRest) != 0 {
				if !reflect.DeepEqual(rest, tt.wantRest) {
					t.Errorf("rest = %v, want %v", rest, tt.wantRest)
				}
			}
		})
	}
}

// TestCollectShareFlags / TestCollectEnvFileFlags guard the bespoke multi-valued
// scanners: they intentionally bypass parseFlags (which is last-wins) and must
// capture EVERY occurrence in BOTH the space and equals forms.
func TestCollectShareFlags(t *testing.T) {
	got := collectShareFlags([]string{"--share", "s1", "--share=s2", "--other", "x", "--share", "s3"})
	want := []string{"s1", "s2", "s3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("collectShareFlags = %v, want %v", got, want)
	}
}

func TestCollectEnvFileFlags(t *testing.T) {
	got := collectEnvFileFlags([]string{"--env-file", "prod=prod.env", "--env-file=stage=stage.env"})
	want := []string{"prod=prod.env", "stage=stage.env"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("collectEnvFileFlags = %v, want %v", got, want)
	}
}

// collectEnvFlags is multi-valued like the others AND must NOT collide with
// --env-file (which shares the --env prefix): only the exact --env token / --env=
// prefix count. Here --env-file and its value must be ignored entirely.
func TestCollectEnvFlags(t *testing.T) {
	got := collectEnvFlags([]string{
		"--env", "prod", "--env=preprod",
		"--env-file", "prod=prod.env", // must NOT be captured as an env
		"--env-file=staging=stage.env",
	})
	want := []string{"prod", "preprod"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("collectEnvFlags = %v, want %v (must not swallow --env-file)", got, want)
	}
}
