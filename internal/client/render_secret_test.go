package client

import "testing"

// --- Task 4.4: RenderSecretYAML deterministic golden ---------------------------
//
// RenderSecretYAML renders a K8sSecret to a stable k8s Secret manifest:
// apiVersion v1, kind Secret, metadata.name/.namespace, the managed-by label,
// type, and data with base64-encoded values under SORTED keys. Determinism is
// load-bearing — the byte-equivalence harness diffs this output.

// TestRenderSecretYAMLGolden pins the exact bytes for a fixed Opaque secret with
// two data keys given out of order (B before A) to prove key sorting.
func TestRenderSecretYAMLGolden(t *testing.T) {
	s := &K8sSecret{
		Name:      "demoapp-geo-app",
		Namespace: "demoapp",
		Type:      "Opaque",
		Data: map[string][]byte{
			"B_KEY": []byte("two"), // base64("two") = dHdv
			"A_KEY": []byte("one"), // base64("one") = b25l
		},
	}
	// data keys MUST be sorted (A_KEY before B_KEY) regardless of insertion order.
	want := `apiVersion: v1
kind: Secret
metadata:
  name: demoapp-geo-app
  namespace: demoapp
  labels:
    app.kubernetes.io/managed-by: gitseal-materializer
type: Opaque
data:
  A_KEY: b25l
  B_KEY: dHdv
`
	got := string(RenderSecretYAML(s))
	if got != want {
		t.Fatalf("RenderSecretYAML mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestRenderSecretYAMLDocker pins the docker-secret shape: dockerconfigjson type,
// the single .dockerconfigjson data key (base64-encoded).
func TestRenderSecretYAMLDocker(t *testing.T) {
	s := &K8sSecret{
		Name:      "docker-secret",
		Namespace: "demoapp-preprod",
		Type:      "kubernetes.io/dockerconfigjson",
		Data: map[string][]byte{
			".dockerconfigjson": []byte(`{"auths":{}}`), // base64 → eyJhdXRocyI6e319
		},
	}
	want := `apiVersion: v1
kind: Secret
metadata:
  name: docker-secret
  namespace: demoapp-preprod
  labels:
    app.kubernetes.io/managed-by: gitseal-materializer
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: eyJhdXRocyI6e319
`
	got := string(RenderSecretYAML(s))
	if got != want {
		t.Fatalf("RenderSecretYAML(docker) mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestRenderSecretYAMLEmptyData proves an empty-data secret still renders a
// valid manifest with an empty (but present) data block.
func TestRenderSecretYAMLEmptyData(t *testing.T) {
	s := &K8sSecret{Name: "empty", Namespace: "ns", Type: "Opaque", Data: map[string][]byte{}}
	want := `apiVersion: v1
kind: Secret
metadata:
  name: empty
  namespace: ns
  labels:
    app.kubernetes.io/managed-by: gitseal-materializer
type: Opaque
data: {}
`
	got := string(RenderSecretYAML(s))
	if got != want {
		t.Fatalf("RenderSecretYAML(empty) mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}
