package client

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// dns1123Label is the k8s DNS-1123 label grammar (RFC 1123): lowercase
// alphanumerics and internal hyphens, must start and end alphanumeric. Both
// Secret names (demoapp-<svc>-app, docker-secret) and namespaces must already
// satisfy this to be accepted by the API server, so validating against it loses
// nothing — it only rejects inputs that could never have been a valid Secret.
var dns1123Label = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// validDNSLabel reports whether s is a valid k8s DNS-1123 label (≤63 chars,
// matching dns1123Label). This is the by-design guard against YAML-field
// injection in the rendered manifest: the only identifier fields RenderSecretYAML
// interpolates (name, namespace) are validated to this grammar at the boundary,
// so a value carrying ':', a newline, or any YAML metacharacter can never reach
// the manifest — it is rejected fail-closed before a Secret is ever built.
func validDNSLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	return dns1123Label.MatchString(s)
}

// dockerSecretSvc is the one service whose materialized Secret is a k8s docker
// pull credential rather than a plain Opaque app secret. Its plaintext value is
// the docker config JSON, stored under a single bundle entry; the k8s Secret
// exposes it under the well-known .dockerconfigjson key with the dockerconfigjson
// type (per the design's Resolved Decisions / R4, matching the retiring bitnami
// SealedSecret metadata.name=docker-secret, type=kubernetes.io/dockerconfigjson,
// single key .dockerconfigjson).
const (
	dockerSecretSvc  = "docker-secret"
	dockerConfigKey  = ".dockerconfigjson"
	dockerConfigType = "kubernetes.io/dockerconfigjson"
	opaqueType       = "Opaque"

	// ManagedByLabel marks every Secret the materializer writes, so it can prune
	// its own orphans (and only its own) without touching operator- or human-
	// managed Secrets in the same namespace.
	ManagedByLabelKey   = "app.kubernetes.io/managed-by"
	ManagedByLabelValue = "gitseal-materializer"
)

// MaterializeInput carries the per-Job wiring the materializer runs under: the
// selected env, the target namespace, this Job's OWN cluster (from GITSEAL_CLUSTER
// / the mounted key), and the mounted cluster Identity used to decrypt. Identity
// is the age private key bytes; it is copied per-entry before decrypt so
// UnsealVerified's zeroize-on-return does not clobber it between entries.
type MaterializeInput struct {
	Env       string
	Namespace string
	Cluster   string
	Identity  []byte
	// ProjectID re-asserted against each AEAD envelope. v2 bundles carried it
	// in-file; v3 dropped it (normalized), so the materializer supplies it from
	// .seald/repo.yaml (which it git-clones alongside .sealed/) — keeping the
	// materializer registry-independent. 0 = use the bundle's own (v2 back-compat).
	ProjectID int64
	// Recipient is the project PUBKEY re-asserted against each v4 AEAD
	// envelope, supplied from .seald/repo.yaml (the sole identity a v4 repo.yaml
	// carries). Required for a v4 bundle; ignored for v1-v3 (which use ProjectID).
	Recipient string
	// SecretPrefix is prepended to the materialized Opaque Secret name:
	// name = <SecretPrefix><svc>-app. Set per tenant via GITSEAL_SECRET_PREFIX
	// (e.g. "demoapp-", "app1-"). Empty (default) → "<svc>-app". This makes the
	// materializer tenant-agnostic; the deploy repo's chart passes its own prefix.
	// (dockerSecretSvc is exempt — it always materializes as `docker-secret`.)
	SecretPrefix string
}

// K8sSecret is the minimal, decrypted k8s Secret shape the materializer emits —
// just the load-bearing fields (name, namespace, type, data). It is rendered to
// YAML (RenderSecretYAML) and applied via kubectl; no client-go types are pulled
// into this security-critical path (lessons.md L7).
type K8sSecret struct {
	Name      string
	Namespace string
	Type      string
	Data      map[string][]byte
}

// BuildSecretForBundle is the materializer read core and mandatory gate #2
// (fail-closed cluster cross-check). Given a v2 bundle, the service name, and the
// per-Job MaterializeInput, it:
//
//  1. selects the in.Env section — a MISSING env is an error (never a partial),
//  2. CROSS-CHECKS the section's declared cluster == in.Cluster BEFORE any
//     decrypt — a mismatch ABORTS (this catches a wrong-env Job wiring even
//     before the crypto would, e.g. a staging Job pointed at a example prod
//     section: it aborts here rather than merely failing to decrypt),
//  3. decrypts EVERY entry in that section with in.Identity via
//     crypto.UnsealVerified, re-asserting b.ProjectID (so a cross-repo blob
//     cannot smuggle in) — ANY decrypt failure aborts the whole build,
//  4. returns the assembled K8sSecret (all-or-nothing).
//
// It never returns a partial Secret: on any error the returned *K8sSecret is nil.
// The materializer applies Secrets only from a fully-built result, so a failure
// here blocks the sync rather than shipping stale/partial secrets (gate #2).
func BuildSecretForBundle(b *SealedBundle, svc string, in MaterializeInput) (*K8sSecret, error) {
	if !IsPerEnvVersion(b.Version) {
		return nil, fmt.Errorf("bundle for %q is %q, materialize requires a per-env bundle (v2/v3/v4)", svc, b.Version)
	}

	// (1) select the env section — missing env is a hard error.
	sec, ok := b.Envs[in.Env]
	if !ok {
		return nil, fmt.Errorf("materialize %s: env %q absent from bundle", svc, in.Env)
	}

	// (2) FAIL-CLOSED cluster cross-check. v2 bundles carry a `cluster` label we can
	// cross-check BEFORE decrypt (catches wrong-env wiring early). v3
	// dropped the label — the cross-check is CRYPTO: a section sealed to another
	// cluster's key simply won't decrypt with in.Identity (step 3), which is the
	// real, unfakeable gate #2 (the label was always advisory, L1). So: check the
	// label when present; otherwise rely on the crypto below (decrypt-what-you-can).
	if sec.Cluster != "" && sec.Cluster != in.Cluster {
		return nil, fmt.Errorf(
			"materialize %s: cluster cross-check FAILED for env %q: section cluster %q != this cluster %q (aborting before decrypt)",
			svc, in.Env, sec.Cluster, in.Cluster)
	}

	// Resolve the anti-splice discriminator to re-assert against each AEAD envelope.
	// v4: the embedded project PUBKEY == in.Recipient (from repo.yaml).
	// v1-v3: the numeric project_id (v3 supplies it via input; v2 uses the bundle's
	// own field). Exactly one applies per bundle version.
	isV4 := b.Version == BundleVersionV4
	var projectID int64
	if isV4 {
		if in.Recipient == "" {
			return nil, fmt.Errorf("materialize %s: v4 bundle requires MaterializeInput.Recipient (project pubkey from repo.yaml)", svc)
		}
	} else {
		projectID = in.ProjectID
		if projectID == 0 {
			projectID = b.ProjectID
		}
		if projectID == 0 {
			return nil, fmt.Errorf("materialize %s: no project_id (v3 requires MaterializeInput.ProjectID from repo.yaml)", svc)
		}
	}

	// (3) decrypt every entry with the mounted identity, re-asserting the
	// discriminator. Sort names for deterministic behavior + stable error reporting.
	names := make([]string, 0, len(sec.Entries))
	for n := range sec.Entries {
		names = append(names, n)
	}
	sort.Strings(names)

	data := make(map[string][]byte, len(sec.Entries))
	for _, name := range names {
		ct := b.EnvCiphertext(in.Env, name)
		if ct == nil {
			return nil, fmt.Errorf("materialize %s: entry %q/%q unreadable (bad base64)", svc, in.Env, name)
		}
		// UnsealVerified* zeroizes the identity slice it is given, so hand it a
		// fresh copy per entry (the mounted key must survive across entries).
		id := append([]byte(nil), in.Identity...)
		var pt []byte
		var err error
		if isV4 {
			pt, _, err = crypto.UnsealVerifiedByKey(ct, id, in.Recipient)
		} else {
			pt, _, err = crypto.UnsealVerified(ct, id, projectID)
		}
		if err != nil {
			return nil, fmt.Errorf("materialize %s: decrypt %q/%q failed: %w", svc, in.Env, name, err)
		}
		data[name] = pt
	}

	return assembleSecret(svc, in.Namespace, in.SecretPrefix, data)
}

// assembleSecret maps a service's decrypted name→value data into the k8s Secret
// shape, applying the docker-secret special case. For docker-secret the single
// decrypted value is re-keyed under .dockerconfigjson and the type is
// kubernetes.io/dockerconfigjson; every other service is a plain Opaque
// <prefix><svc>-app Secret whose data keys are the entry names verbatim. prefix is
// the tenant discriminator (GITSEAL_SECRET_PREFIX, e.g. "demoapp-"/"app1-"); "" → "<svc>-app".
func assembleSecret(svc, namespace, prefix string, data map[string][]byte) (*K8sSecret, error) {
	// Fail-closed boundary validation — the impossible-by-design guard against
	// YAML-field injection. svc, namespace and prefix are the only inputs that flow
	// into the manifest's interpolated identifier fields (name via prefix+svc+"-app",
	// namespace verbatim); all MUST yield a valid k8s DNS-1123 label. A svc, namespace
	// or prefix carrying ':' or a newline is rejected here — never emitted. (Both
	// the materialize path and any future caller reach RenderSecretYAML only
	// through this single chokepoint, so validating here covers them all.)
	if !validDNSLabel(svc) {
		return nil, fmt.Errorf("materialize: invalid service name %q (must be a DNS-1123 label: lowercase alphanumerics and internal hyphens, ≤63 chars)", svc)
	}
	if !validDNSLabel(namespace) {
		return nil, fmt.Errorf("materialize %s: invalid namespace %q (must be a DNS-1123 label: lowercase alphanumerics and internal hyphens, ≤63 chars)", svc, namespace)
	}

	if svc == dockerSecretSvc {
		if len(data) != 1 {
			return nil, fmt.Errorf("materialize %s: expected exactly 1 entry (the docker config), got %d", svc, len(data))
		}
		var val []byte
		for _, v := range data { // the sole entry, whatever its stored key name
			val = v
		}
		return &K8sSecret{
			Name:      dockerSecretSvc,
			Namespace: namespace,
			Type:      dockerConfigType,
			Data:      map[string][]byte{dockerConfigKey: val},
		}, nil
	}
	name := prefix + svc + "-app"
	if !validDNSLabel(name) {
		return nil, fmt.Errorf("materialize %s: computed Secret name %q (prefix %q) is not a valid DNS-1123 label", svc, name, prefix)
	}
	return &K8sSecret{
		Name:      name,
		Namespace: namespace,
		Type:      opaqueType,
		Data:      data,
	}, nil
}

// ServiceFromBundlePath derives a service name from a .sealed/<svc>.app.json path
// (basename minus the ".app.json" suffix), so the materializer's glob can name
// each bundle's Secret.
func ServiceFromBundlePath(path string) string {
	return strings.TrimSuffix(filepath.Base(path), ".app.json")
}
