package client

import (
	"sort"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// MintEnvMaterializerKeys mints a FRESH per-env materializer keypair for a project
// being onboarded, given the fleet's env TOPOLOGY (cluster, namespace,
// min_level — any recipient in the input is IGNORED). It returns the envs with the
// freshly-minted recipients (to write into the project's projects.json entry) plus
// each env's private identity (to seed the out-of-band per-env materializer Secret
// gitseal-materializer-<project>-<env>). This is what makes the materializer key
// per-(project,env) instead of fleet-shared: a new project never reuses another
// project's key.
func MintEnvMaterializerKeys(topology map[string]RegistryEnv) (envs map[string]RegistryEnv, identities map[string]string, err error) {
	envs = map[string]RegistryEnv{}
	identities = map[string]string{}
	for _, env := range sortedEnvNames(topology) {
		t := topology[env]
		kp, gerr := crypto.GenerateRepoKey()
		if gerr != nil {
			return nil, nil, gerr
		}
		envs[env] = RegistryEnv{
			Cluster:   t.Cluster,
			Namespace: t.Namespace,
			MinLevel:  t.MinLevel,
			Recipient: kp.Recipient, // FRESH per-(project,env) recipient
		}
		identities[env] = kp.Identity
	}
	return envs, identities, nil
}

func sortedEnvNames(m map[string]RegistryEnv) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
