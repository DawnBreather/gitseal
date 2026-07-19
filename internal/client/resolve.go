package client

// ResolveEnvs computes the per-env plaintext matrix for v2 authoring: for each
// env in `envs` it starts from a fresh COPY of `base` and overlays that env's
// entry in `overrides` (per-key last-wins), returning env → (KEY → value).
//
// It is pure (no I/O) and produces independent maps — no env's resolved map
// shares backing storage with `base`, another env, or the caller's overrides,
// so a downstream mutation of one cannot bleed into another. A nil/absent
// override for an env replicates the base verbatim; an empty `envs` yields an
// empty (non-nil) result.
//
// This is the DRY authoring core (design "Authoring", DRY common + divergent):
// the human types the common values ONCE in base.env and only the divergent keys
// in each --env-file; SealBundleV2 then fans the resolved values out per-cluster.
func ResolveEnvs(base map[string]string, overrides map[string]map[string]string, envs []string) map[string]map[string]string {
	out := make(map[string]map[string]string, len(envs))
	for _, env := range envs {
		m := make(map[string]string, len(base))
		for k, v := range base {
			m[k] = v
		}
		for k, v := range overrides[env] { // nil override → no-op range
			m[k] = v
		}
		out[env] = m
	}
	return out
}
