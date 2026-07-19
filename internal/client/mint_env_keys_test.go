package client

import (
	"testing"

	"filippo.io/age"
)

// MintEnvMaterializerKeys takes the fleet's env TOPOLOGY (cluster,
// namespace, min_level — recipients ignored) and mints a FRESH materializer
// keypair per env for THIS project, so a new project never shares another
// project's materializer key. Returns the envs with fresh recipients (for the
// registry entry) + the private identities (to seed the per-env Secrets
// out-of-band). Each identity's recipient must match the env's new recipient.
func TestMintEnvMaterializerKeys(t *testing.T) {
	topology := map[string]RegistryEnv{
		"prod":    {Cluster: "example", Namespace: "demoapp", MinLevel: 40, Recipient: "age1SHARED"}, // recipient ignored
		"preprod": {Cluster: "example", Namespace: "demoapp-preprod", MinLevel: 40, Recipient: "age1SHARED"},
		"staging": {Cluster: "staging", Namespace: "demoapp", MinLevel: 30, Recipient: "age1SHARED"},
	}
	envs, idents, err := MintEnvMaterializerKeys(topology)
	if err != nil {
		t.Fatalf("MintEnvMaterializerKeys: %v", err)
	}
	if len(envs) != 3 || len(idents) != 3 {
		t.Fatalf("expected 3 envs + 3 identities, got %d/%d", len(envs), len(idents))
	}
	seen := map[string]bool{}
	for env, cfg := range envs {
		// topology preserved
		if cfg.Cluster != topology[env].Cluster || cfg.Namespace != topology[env].Namespace || cfg.MinLevel != topology[env].MinLevel {
			t.Fatalf("env %q topology not preserved: %+v", env, cfg)
		}
		// recipient is FRESH (not the shared placeholder) + distinct per env
		if cfg.Recipient == "age1SHARED" || cfg.Recipient == "" {
			t.Fatalf("env %q recipient not freshly minted: %q", env, cfg.Recipient)
		}
		if seen[cfg.Recipient] {
			t.Fatalf("env %q recipient collides with another env", env)
		}
		seen[cfg.Recipient] = true
		// the identity resolves to exactly this recipient
		id, err := age.ParseX25519Identity(idents[env])
		if err != nil {
			t.Fatalf("env %q identity invalid: %v", env, err)
		}
		if id.Recipient().String() != cfg.Recipient {
			t.Fatalf("env %q: identity recipient %q != env recipient %q", env, id.Recipient(), cfg.Recipient)
		}
	}
}
