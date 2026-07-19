package client

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
)

// RenderSecretYAML renders a K8sSecret to a deterministic k8s Secret manifest.
//
// The output is hand-built (not via a YAML marshaller) so it is byte-stable: the
// byte-equivalence cutover harness diffs this against the retiring bitnami
// output, so field order, the managed-by label, the base64 `data` encoding, and
// SORTED data keys must all be fixed. Every rendered Secret carries
// app.kubernetes.io/managed-by: gitseal-materializer so the materializer can
// prune exactly its own orphans (and nothing else) in the target namespace.
func RenderSecretYAML(s *K8sSecret) []byte {
	var b strings.Builder
	b.WriteString("apiVersion: v1\n")
	b.WriteString("kind: Secret\n")
	b.WriteString("metadata:\n")
	fmt.Fprintf(&b, "  name: %s\n", s.Name)
	fmt.Fprintf(&b, "  namespace: %s\n", s.Namespace)
	b.WriteString("  labels:\n")
	fmt.Fprintf(&b, "    %s: %s\n", ManagedByLabelKey, ManagedByLabelValue)
	fmt.Fprintf(&b, "type: %s\n", s.Type)

	if len(s.Data) == 0 {
		b.WriteString("data: {}\n")
		return []byte(b.String())
	}

	keys := make([]string, 0, len(s.Data))
	for k := range s.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	b.WriteString("data:\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "  %s: %s\n", k, base64.StdEncoding.EncodeToString(s.Data[k]))
	}
	return []byte(b.String())
}
