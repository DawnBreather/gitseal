package client

import (
	"fmt"
	"sort"
	"strings"
)

// RenderTree produces a human-readable tree of a v3 bundle: per-env key names +
// the signer fingerprint, WITHOUT ciphertext blobs. "structure + authorship at a
// glance" (ergonomics). svcName heads the tree; unsigned sections show
// "(unsigned)".
func RenderTree(svcName string, b *SealedBundle) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s\n", svcName)
	envs := make([]string, 0, len(b.Envs))
	for e := range b.Envs {
		envs = append(envs, e)
	}
	sort.Strings(envs)
	for i, env := range envs {
		sec := b.Envs[env]
		branch := "├─"
		if i == len(envs)-1 {
			branch = "└─"
		}
		keys := make([]string, 0, len(sec.Entries))
		for k := range sec.Entries {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		signer := "(unsigned)"
		if sec.Sig != nil && sec.Sig.By != "" {
			signer = "✍ " + sec.Sig.By
		}
		fmt.Fprintf(&sb, "%s %-9s %s   %s\n", branch, env, strings.Join(keys, " "), signer)
	}
	return sb.String()
}
