package client

import (
	"encoding/base64"
	"testing"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// --- Task 4.3: BuildSecretForBundle fail-closed cluster cross-check ------------
//
// BuildSecretForBundle is the materializer's read core (mandatory gate #2). It
// cross-checks b.Envs[in.Env].Cluster == in.Cluster BEFORE decrypting anything,
// then decrypts that section's entries with in.Identity via UnsealVerified
// (re-asserting b.ProjectID) and returns the k8s Secret shape. It errors — never
// returns a partial Secret — on env-missing, cluster-mismatch, or any decrypt
// failure.

// sealV2Section is a test helper that builds a v2 SealedBundle with one env
// section, each entry sealed to [human, cluster] via crypto.SealMulti.
func sealV2Section(t *testing.T, projectID int64, human, clusterRecip, clusterName, env string, kv map[string]string) *SealedBundle {
	t.Helper()
	entries := map[string]string{}
	for k, v := range kv {
		ct, err := crypto.SealMulti([]byte(v), []string{human, clusterRecip}, projectID, k, 30)
		if err != nil {
			t.Fatalf("SealMulti %s: %v", k, err)
		}
		entries[k] = base64.StdEncoding.EncodeToString(ct)
	}
	return &SealedBundle{
		Kind:      "SealedBundle",
		Version:   "v2",
		ProjectID: projectID,
		Recipients: map[string]string{
			"human":     human,
			clusterName: clusterRecip,
		},
		Envs: map[string]EnvSection{
			env: {Cluster: clusterName, Entries: entries},
		},
	}
}

// TestMaterializeClusterCrossCheckFailClosed is the Phase 4 key test. It proves
// the whole fail-closed contract in one place.
func TestMaterializeClusterCrossCheckFailClosed(t *testing.T) {
	const pid = int64(338)
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey() // example
	s, _ := crypto.GenerateRepoKey() // staging (its identity must NEVER decrypt a G section)

	// A v2 bundle: prod section sealed to [human, G], cluster "example".
	b := sealV2Section(t, pid, human.Recipient, g.Recipient, "example", "prod", map[string]string{"A": "v"})

	// (2) A STAGING Job (Cluster:"staging", Identity:S) pointed at the prod section
	// must ABORT on the cluster cross-check BEFORE any decrypt — and it would fail
	// to decrypt anyway (S is not a recipient), but the point is it never tries.
	sec, err := BuildSecretForBundle(b, "geo", MaterializeInput{
		Env: "prod", Namespace: "demoapp", Cluster: "staging", Identity: []byte(s.Identity),
	})
	if err == nil {
		t.Fatal("SECURITY FAILURE: staging Job on a example (prod) section did not abort")
	}
	if sec != nil {
		t.Fatalf("cross-check abort must return a nil secret, got %+v", sec)
	}

	// (3) The CORRECT wiring (Cluster:"example", Identity:G) succeeds with the
	// right name/namespace/type/data.
	sec, err = BuildSecretForBundle(b, "geo", MaterializeInput{
		Env: "prod", Namespace: "demoapp", Cluster: "example", Identity: []byte(g.Identity), SecretPrefix: "demoapp-",
	})
	if err != nil {
		t.Fatalf("correct wiring should build the secret: %v", err)
	}
	if sec.Name != "demoapp-geo-app" {
		t.Fatalf("name: got %q want demoapp-geo-app", sec.Name)
	}
	if sec.Namespace != "demoapp" {
		t.Fatalf("namespace: got %q want demoapp", sec.Namespace)
	}
	if sec.Type != "Opaque" {
		t.Fatalf("type: got %q want Opaque", sec.Type)
	}
	if string(sec.Data["A"]) != "v" {
		t.Fatalf("data[A]: got %q want v", sec.Data["A"])
	}

	// (4) docker-secret naming/type: name "docker-secret", type dockerconfigjson,
	// the single decrypted value keyed as ".dockerconfigjson".
	db := sealV2Section(t, pid, human.Recipient, g.Recipient, "example", "prod",
		map[string]string{"config": `{"auths":{}}`})
	dsec, err := BuildSecretForBundle(db, "docker-secret", MaterializeInput{
		Env: "prod", Namespace: "demoapp", Cluster: "example", Identity: []byte(g.Identity),
	})
	if err != nil {
		t.Fatalf("docker-secret build: %v", err)
	}
	if dsec.Name != "docker-secret" {
		t.Fatalf("docker name: got %q want docker-secret", dsec.Name)
	}
	if dsec.Type != "kubernetes.io/dockerconfigjson" {
		t.Fatalf("docker type: got %q want kubernetes.io/dockerconfigjson", dsec.Type)
	}
	if string(dsec.Data[".dockerconfigjson"]) != `{"auths":{}}` {
		t.Fatalf("docker data[.dockerconfigjson]: got %q", dsec.Data[".dockerconfigjson"])
	}
	if len(dsec.Data) != 1 {
		t.Fatalf("docker secret must have exactly one key, got %d", len(dsec.Data))
	}

	// (5) An env missing from the bundle is an error (never a partial/empty secret).
	sec, err = BuildSecretForBundle(b, "geo", MaterializeInput{
		Env: "staging", Namespace: "demoapp", Cluster: "staging", Identity: []byte(s.Identity),
	})
	if err == nil {
		t.Fatal("missing env should error")
	}
	if sec != nil {
		t.Fatalf("missing env must return nil secret, got %+v", sec)
	}
}

// TestBuildSecretDecryptFailureIsError proves a decrypt failure (wrong identity
// that still passes the cluster label check because the caller lied about the
// cluster name but supplied a non-recipient identity) errors rather than
// returning a partial secret. Here the section is [human, G] cluster "example"
// but we pass S's identity WITH Cluster "example" (label matches, key does
// not) — decrypt must fail closed.
func TestBuildSecretDecryptFailureIsError(t *testing.T) {
	const pid = int64(338)
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey()
	s, _ := crypto.GenerateRepoKey()

	b := sealV2Section(t, pid, human.Recipient, g.Recipient, "example", "prod", map[string]string{"A": "v"})

	sec, err := BuildSecretForBundle(b, "geo", MaterializeInput{
		Env: "prod", Namespace: "demoapp", Cluster: "example", Identity: []byte(s.Identity),
	})
	if err == nil {
		t.Fatal("decrypt with a non-recipient identity must error")
	}
	if sec != nil {
		t.Fatalf("decrypt failure must return nil secret, got %+v", sec)
	}
}

// --- Security hardening: DNS-1123-label validation (no YAML-field injection) ---
//
// svc (from ServiceFromBundlePath, i.e. the .sealed/<svc>.app.json basename) and
// in.Namespace (Job wiring) are the only inputs that flow into RenderSecretYAML's
// interpolated identifier fields (name = demoapp-<svc>-app, namespace verbatim).
// BuildSecretForBundle validates both as k8s DNS-1123 labels at the assembleSecret
// chokepoint and fails closed on anything that could break the manifest — a ':',
// a newline, an uppercase char, etc. — so YAML-field injection is impossible by
// design. These tests pin that: bad svc/namespace → error + nil secret; real
// hyphenated svc names and normal namespaces still succeed.

// buildSvc seals a one-entry prod section to [human, G] cluster "example" and
// materializes it for the given svc + namespace with the CORRECT (G) wiring, so
// the only thing under test is the svc/namespace label validation.
func buildSvc(t *testing.T, svc, namespace string) (*K8sSecret, error) {
	t.Helper()
	const pid = int64(338)
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey()
	b := sealV2Section(t, pid, human.Recipient, g.Recipient, "example", "prod", map[string]string{"A": "v"})
	return BuildSecretForBundle(b, svc, MaterializeInput{
		Env: "prod", Namespace: namespace, Cluster: "example", Identity: []byte(g.Identity), SecretPrefix: "demoapp-",
	})
}

func TestBuildSecretRejectsBadServiceName(t *testing.T) {
	// Each of these svc values, if interpolated verbatim into "demoapp-<svc>-app",
	// would break the manifest (': ' opens a mapping value; '\n' opens a new
	// field; uppercase is not a valid label). All must fail closed.
	bad := map[string]string{
		"colon":       "geo:evil",
		"newline":     "bad\nname",
		"crlf":        "svc\r\nnamespace: attacker",
		"leadinghyp":  "-geo",
		"trailinghyp": "geo-",
		"uppercase":   "Geo",
		"empty":       "",
		"space":       "geo evil",
	}
	for label, svc := range bad {
		t.Run(label, func(t *testing.T) {
			sec, err := buildSvc(t, svc, "demoapp")
			if err == nil {
				t.Fatalf("SECURITY FAILURE: svc %q was accepted; must fail closed", svc)
			}
			if sec != nil {
				t.Fatalf("invalid svc %q must return nil secret, got %+v", svc, sec)
			}
		})
	}

	// Real, hyphenated service names MUST still pass — the regex allows internal
	// hyphens, and these are actual demoapp svc names.
	for _, svc := range []string{"geo", "audit-logs", "location-ingest"} {
		t.Run("ok/"+svc, func(t *testing.T) {
			sec, err := buildSvc(t, svc, "demoapp")
			if err != nil {
				t.Fatalf("valid svc %q must succeed: %v", svc, err)
			}
			if sec == nil {
				t.Fatalf("valid svc %q must return a secret", svc)
			}
			if want := "demoapp-" + svc + "-app"; sec.Name != want {
				t.Fatalf("svc %q: name got %q want %q", svc, sec.Name, want)
			}
		})
	}
}

func TestBuildSecretRejectsBadNamespace(t *testing.T) {
	bad := map[string]string{
		"newline":   "ns\ninjection",
		"colon":     "ns:evil",
		"crlf":      "ns\r\n  name: attacker",
		"uppercase": "Demoapp",
		"empty":     "",
		"space":     "demoapp preprod",
	}
	for label, ns := range bad {
		t.Run(label, func(t *testing.T) {
			sec, err := buildSvc(t, "geo", ns)
			if err == nil {
				t.Fatalf("SECURITY FAILURE: namespace %q was accepted; must fail closed", ns)
			}
			if sec != nil {
				t.Fatalf("invalid namespace %q must return nil secret, got %+v", ns, sec)
			}
		})
	}

	// Real namespaces (incl. the hyphenated pre-prod one) MUST still pass.
	for _, ns := range []string{"demoapp", "demoapp-preprod"} {
		t.Run("ok/"+ns, func(t *testing.T) {
			sec, err := buildSvc(t, "geo", ns)
			if err != nil {
				t.Fatalf("valid namespace %q must succeed: %v", ns, err)
			}
			if sec == nil || sec.Namespace != ns {
				t.Fatalf("valid namespace %q: got %+v", ns, sec)
			}
		})
	}
}

// GITSEAL_SECRET_PREFIX behavior: empty prefix → "<svc>-app" (tenant-agnostic default);
// a set prefix → "<prefix><svc>-app" (demoapp-parity + per-tenant discrimination).
func TestSecretPrefix(t *testing.T) {
	human, _ := crypto.GenerateRepoKey()
	g, _ := crypto.GenerateRepoKey()
	b := sealV2Section(t, 359, human.Recipient, g.Recipient, "prod-cluster", "prod", map[string]string{"K": "v"})
	base := MaterializeInput{Env: "prod", Namespace: "app1", Cluster: "prod-cluster", Identity: []byte(g.Identity)}

	// default: empty prefix → "<svc>-app"
	sec, err := BuildSecretForBundle(b, "app1-backend", base)
	if err != nil {
		t.Fatalf("empty-prefix build: %v", err)
	}
	if sec.Name != "app1-backend-app" {
		t.Fatalf("empty prefix: got %q want app1-backend-app", sec.Name)
	}

	// set prefix → "<prefix><svc>-app"
	pin := base
	pin.SecretPrefix = "demoapp-"
	sec, err = BuildSecretForBundle(b, "geo", pin)
	if err != nil {
		t.Fatalf("prefixed build: %v", err)
	}
	if sec.Name != "demoapp-geo-app" {
		t.Fatalf("set prefix: got %q want demoapp-geo-app", sec.Name)
	}
}
