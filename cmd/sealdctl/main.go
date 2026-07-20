// Command sealdctl is the gitseal laptop CLI.
//
// Primary interface is per-service, per-environment bundles (.sealed/<svc>.app.json),
// driven by --svc/--env:
//
//	sealdctl seal    --svc SVC --from f.env     (offline; encrypts to the repo pubkey)
//	sealdctl unseal  --svc SVC --env ENV        (calls the broker with your glab PAT)
//	sealdctl doctor                             (checks PAT + repo config)
//
// A flat, single-environment mode (--name/--value/--out) is also supported. Other
// subcommands: reseal, verify, verify-keys, tree, env, migrate-v3, migrate-v4,
// migrate-env, materialize, admin. Run `sealdctl <cmd> -h` for flags.
//
// Config (env, with defaults):
//
//	SEALD_BROKER   broker base URL (default https://seald.example.com)
//	SEALD_HOST     GitLab host for PAT resolution (default gitlab.example.com)
//	GITLAB_TOKEN   optional explicit PAT (else glab is consulted)
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"

	"github.com/dawnbreather/gitseal/internal/client"
	"github.com/dawnbreather/gitseal/internal/crypto"
)

func jsonMarshal(v any) (string, error) { b, e := json.Marshal(v); return string(b), e }

const (
	defaultBroker = "https://seald.example.com"
	defaultHost   = "gitlab.example.com"
)

// version is stamped at release time via -ldflags "-X main.version=...".
// Defaults to "dev" for `go install` / source builds.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Println("sealdctl", version)
	case "seal":
		cmdSeal(os.Args[2:])
	case "reseal":
		cmdReseal(os.Args[2:])
	case "unseal":
		cmdUnseal(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "verify-keys":
		cmdVerifyKeys(os.Args[2:])
	case "tree":
		cmdTree(os.Args[2:])
	case "env":
		cmdEnv(os.Args[2:])
	case "migrate-v3":
		cmdMigrateV3(os.Args[2:])
	case "migrate-v4":
		cmdMigrateV4(os.Args[2:])
	case "migrate-env":
		cmdMigrateEnv(os.Args[2:])
	case "materialize":
		cmdMaterialize(os.Args[2:])
	case "doctor":
		cmdDoctor()
	case "admin":
		cmdAdmin(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

// cmdAdmin handles the escrow/root-key admin subcommands:
//
//	add-repo  — prints the public recipient + a KEK-wrapped bundle entry (no plaintext key).
//	gen-root  — generates the seald-root keypair, Shamir-splits the PRIVATE key into shares.
//	combine   — reconstructs the PRIVATE identity from >= threshold shares (seeds the
//	            materializer Secret). SECURITY: combine emits a PRIVATE key — see cmdAdminCombine.
func cmdAdmin(args []string) {
	if len(args) < 1 {
		fail("usage: sealdctl admin <add-repo|gen-root|combine> [flags]")
	}
	switch args[0] {
	case "add-repo":
		flags, _ := parseFlags(args[1:])
		pid := flags["project-id"]
		if pid == "" {
			fail("admin add-repo requires --project-id")
		}
		recipient, entry, err := client.AddRepoKey()
		if err != nil {
			fail("%v", err)
		}
		eb, _ := jsonMarshal(map[string]any{pid: entry})
		fmt.Printf("# .seald/repo.yaml (commit to the repo):\nproject_id: %s\nrecipient: %s\n\n", pid, recipient)
		fmt.Printf("# add this entry to the seald bundle (private key is KEK-wrapped):\n%s\n", eb)
	case "gen-root":
		flags, _ := parseFlags(args[1:])
		n, tt := 3, 2
		if v := flags["shares"]; v != "" {
			fmt.Sscanf(v, "%d", &n)
		}
		if v := flags["threshold"]; v != "" {
			fmt.Sscanf(v, "%d", &tt)
		}
		recipient, shares, err := client.GenRoot(n, tt)
		if err != nil {
			fail("%v", err)
		}
		fmt.Printf("# seald-root public recipient (escrow/DR anchor):\n%s\n\n", recipient)
		fmt.Printf("# %d Shamir shares (threshold %d) — distribute to custodians, NEVER commit:\n", n, tt)
		for i, s := range shares {
			fmt.Printf("share-%d: %s\n", i+1, s)
		}
	case "combine":
		cmdAdminCombine(args[1:])
	case "escrow-check":
		cmdAdminEscrowCheck(args[1:])
	case "onboard":
		cmdAdminOnboard(args[1:])
	case "migrate-keystore":
		cmdAdminMigrateKeystore(args[1:])
	case "env":
		cmdAdminEnv(args[1:])
	default:
		fail("unknown admin subcommand %q (add-repo|onboard|env|migrate-keystore|gen-root|combine|escrow-check)", args[0])
	}
}

// cmdAdminEnv configures a project's ENVIRONMENTS in the git-tracked registry
// projects.json — the reviewed-config path that replaces the pre-v4
// repo.yaml edit (CODEOWNERS-gated MR):
//
//	# in infra-repo: apps/seald/manifests/registry/projects.json (the git ConfigMap source)
//	sealdctl admin env set --file <path>/projects.json --project <pubkey> \
//	    --env qa --cluster example --min-level 40 [--add-cluster example=age1G]
//	sealdctl admin env rm  --file <path>/projects.json --project <pubkey> --env qa
//	sealdctl admin env list --file <path>/projects.json   # dump the whole registry
//
// It mutates the file in place (fail-closed on unknown cluster / project_id
// mismatch / absent env), then the admin commits it → reviewed MR → ArgoCD syncs
// the ConfigMap → the broker hot-reloads. NEVER touches users.json / the service
// token (those stay in the out-of-band Secret). project_id is optional on `set`
// for an existing entry; required to create one.
func cmdAdminEnv(args []string) {
	if len(args) == 0 {
		fail("usage: sealdctl admin env <set|rm|list> --file projects.json [flags]")
	}
	sub := args[0]
	flags, _ := parseFlags(args[1:])
	file := flags["file"]
	if file == "" {
		fail("admin env %s requires --file <path to projects.json>", sub)
	}
	data, err := os.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		fail("read %s: %v", file, err)
	}
	reg, err := client.ParseProjectRegistry(data)
	if err != nil {
		fail("%v", err)
	}

	switch sub {
	case "list":
		out, _ := reg.MarshalJSON2()
		fmt.Println(string(out))
		return
	case "set":
		pub := flags["project"]
		if pub == "" {
			fail("admin env set requires --project <pubkey>")
		}
		var pid int64
		if v := flags["project-id"]; v != "" {
			fmt.Sscanf(v, "%d", &pid)
		}
		env := flags["env"]
		if env == "" {
			fail("admin env set requires --env NAME")
		}
		// an env is {cluster, namespace, min_level, recipient}. The
		// recipient is the env's OWN age public key (distinct per env even on a
		// shared cluster) — mint it with `admin onboard` for a cluster/env, or pass
		// an existing one here.
		var minLevel int
		if v := flags["min-level"]; v != "" {
			fmt.Sscanf(v, "%d", &minLevel)
		}
		cfg := client.RegistryEnv{
			Cluster:   flags["cluster"],
			Namespace: flags["namespace"],
			MinLevel:  minLevel,
			Recipient: flags["recipient"],
		}
		if cfg.Cluster == "" || cfg.Namespace == "" || cfg.Recipient == "" || minLevel == 0 {
			fail("admin env set --env requires --cluster, --namespace, --min-level, --recipient (the env's age public key)")
		}
		if err := reg.SetEnvV2(pub, pid, env, cfg); err != nil {
			fail("%v", err)
		}
	case "rm":
		pub := flags["project"]
		env := flags["env"]
		if pub == "" || env == "" {
			fail("admin env rm requires --project <pubkey> --env NAME")
		}
		if err := reg.RemoveEnv(pub, env); err != nil {
			fail("%v", err)
		}
	default:
		fail("unknown admin env subcommand %q (set|rm|list)", sub)
	}

	out, err := reg.MarshalJSON2()
	if err != nil {
		fail("%v", err)
	}
	if flags["apply"] == "true" {
		// write in place — the admin still COMMITS it (reviewed MR); --apply just
		// saves the edit locally rather than printing it.
		if err := os.WriteFile(file, append(out, '\n'), 0o644); err != nil {
			fail("write %s: %v", file, err)
		}
		fmt.Fprintf(os.Stderr, "✓ updated %s — commit it (CODEOWNERS-gated MR) so ArgoCD syncs the broker\n", file)
	} else {
		fmt.Println(string(out))
		fmt.Fprintf(os.Stderr, "\n# (dry-run) write with --apply, then commit %s → reviewed MR\n", file)
	}
}

// NOTE: `admin onboard-user` was REMOVED in — SSH-key onboarding is now
// IMPLICIT: the broker builds the fp→(uid,pubkey) identity index from GitLab itself
// (project members → their profile keys), so a developer with a key on their GitLab
// profile who is a project member needs no manual registration.

// cmdAdminMigrateKeystore is the one-time migration: read the LEGACY
// monolithic bundle.json ({pid: {wrapped_key_b64, kek_b64}}) and emit one v2
// key file (<pid>.key.json, RAW identity, no KEK) per project into --out-dir. This
// RELOCATES existing keys losslessly (unwrap once → store raw) so a repo with
// already-sealed secrets (e.g. 338, 375 entries) keeps its keypair — NO re-seal.
//
//	sealdctl admin migrate-keystore --bundle bundle.json --out-dir keys/ \
//	    [--drop <pid>,<pid>] [--expect <pid>=<recipient>,<pid>=<recipient>]
//
// --drop omits vestigial project ids (e.g. 337 = gitseal itself, no sealed
// secrets). --expect asserts the migrated key for a pid derives EXACTLY the given
// public recipient (from the committed .seald/repo.yaml) — fail-closed, so a
// wrong-key/wrong-unwrap can't migrate a valid-but-wrong identity (adversarial
// review MUST-FIX #2). Every emitted key file is validated (unwraps to a valid age
// identity) AND, when an --expect entry exists for its pid, recipient-verified.
func cmdAdminMigrateKeystore(args []string) {
	flags, _ := parseFlags(args)
	bundlePath := flags["bundle"]
	outDir := flags["out-dir"]
	if bundlePath == "" || outDir == "" {
		fail("admin migrate-keystore requires --bundle <legacy bundle.json> --out-dir <keys dir> [--drop pid,pid] [--expect pid=recipient,...]")
	}
	drop := map[string]bool{}
	for _, d := range strings.Split(flags["drop"], ",") {
		if d = strings.TrimSpace(d); d != "" {
			drop[d] = true
		}
	}
	// --expect pid=recipient[,pid=recipient…]: the public recipient each migrated
	// key MUST derive (fail-closed on mismatch).
	expect := map[string]string{}
	for _, kv := range strings.Split(flags["expect"], ",") {
		if kv = strings.TrimSpace(kv); kv == "" {
			continue
		}
		p, r, ok := strings.Cut(kv, "=")
		if !ok || p == "" || r == "" {
			fail("--expect entry %q must be pid=recipient", kv)
		}
		expect[p] = r
	}
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		fail("read bundle: %v", err)
	}
	var bundle map[string]struct {
		WrappedKeyB64 string `json:"wrapped_key_b64"`
		KEKB64        string `json:"kek_b64"`
	}
	if err := json.Unmarshal(raw, &bundle); err != nil {
		fail("parse bundle: %v", err)
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fail("mkdir out-dir: %v", err)
	}
	migrated, dropped := 0, 0
	for pidStr, e := range bundle {
		if drop[pidStr] {
			fmt.Fprintf(os.Stderr, "  dropped %s (vestigial)\n", pidStr)
			dropped++
			continue
		}
		// MUST-FIX #1: reject a non-numeric / non-positive project id at migration
		// time (fail-closed). Ignoring the Sscanf error would let a bad pid become
		// 0.key.json → silently dropped at broker load → lost key with false success.
		var pid int64
		if _, err := fmt.Sscanf(pidStr, "%d", &pid); err != nil || pid <= 0 {
			fail("bundle has a non-numeric/invalid project id %q — refusing to migrate (fail closed)", pidStr)
		}
		wrapped, err := base64.StdEncoding.DecodeString(e.WrappedKeyB64)
		if err != nil {
			fail("project %s wrapped_key_b64: %v", pidStr, err)
		}
		kek, err := base64.StdEncoding.DecodeString(e.KEKB64)
		if err != nil {
			fail("project %s kek_b64: %v", pidStr, err)
		}
		identity, err := crypto.UnwrapKey(wrapped, kek)
		if err != nil {
			fail("project %s unwrap: %v", pidStr, err)
		}
		kf := client.NewKeyFileV2(pid, string(identity))
		// validate before writing (fail closed): syntactically a valid age key…
		if _, verr := kf.Identity(); verr != nil {
			fail("project %s produced an invalid v2 key: %v", pidStr, verr)
		}
		// MUST-FIX #2: …and, when --expect names this pid, the key must derive the
		// EXACT committed recipient — else a wrong-KEK unwrap would migrate a valid-
		// but-wrong identity, deferring detection to a broker unseal failure.
		if want, ok := expect[pidStr]; ok {
			if verr := kf.Verify(want); verr != nil {
				fail("project %s recipient MISMATCH vs --expect: %v", pidStr, verr)
			}
		}
		out := filepath.Join(outDir, client.KeyFileName(pid))
		kfData, _ := json.MarshalIndent(kf, "", "  ")
		if err := os.WriteFile(out, append(kfData, '\n'), 0600); err != nil {
			fail("write %s: %v", out, err)
		}
		fmt.Fprintf(os.Stderr, "  migrated %s → %s (v2, raw identity)\n", pidStr, out)
		migrated++
	}
	fmt.Printf("migrate-keystore: %d migrated, %d dropped → %s\n", migrated, dropped, outDir)
}

// cmdAdminEscrowCheck REHEARSES a Shamir reconstruction WITHOUT emitting the
// private key — a safe DR drill you can run anytime to prove the escrowed shares
// still reconstruct a working identity (turning "shares discovered broken at DR
// time" into a routine check). It reconstructs from --share/--shares-file, derives
// the public recipient, and — with --expect <recipient> — asserts it matches, then
// prints ONLY the recipient (never the private key) + OK/FAIL. Exits non-zero on
// any failure (fail closed).
//
//	sealdctl admin escrow-check --shares-file custodian-shares.txt --expect age1G…
func cmdAdminEscrowCheck(args []string) {
	flags, _ := parseFlags(args)
	shares := collectShareFlags(args)
	if sf := flags["shares-file"]; sf != "" {
		fileShares, err := readSharesFile(sf)
		if err != nil {
			fail("%v", err)
		}
		shares = append(shares, fileShares...)
	}
	if len(shares) == 0 {
		fail("admin escrow-check requires shares: --share S (repeatable) and/or --shares-file PATH\n" +
			"  This is a SAFE drill: it reconstructs to VERIFY the shares, prints only the\n" +
			"  public recipient, and NEVER emits the private key.")
	}
	identity, err := client.CombineShares(shares)
	if err != nil {
		fail("escrow-check FAILED: shares did not reconstruct: %v", err)
	}
	id, err := age.ParseX25519Identity(identity)
	if err != nil {
		fail("escrow-check FAILED: reconstructed value is not a valid age key: %v", err)
	}
	got := id.Recipient().String()
	fmt.Fprintf(os.Stderr, "reconstructed recipient: %s\n", got)
	if expect := flags["expect"]; expect != "" {
		if got != expect {
			fail("escrow-check FAILED: reconstructed %s != expected %s", got, expect)
		}
		fmt.Println("escrow-check OK: shares reconstruct the expected recipient")
		return
	}
	fmt.Println("escrow-check OK: shares reconstruct a valid identity (pass --expect <recipient> to assert which)")
}

// cmdAdminOnboard is the one-command repo onboarding path (design: dissolve the
// monolith + zero-touch onboarding). It replaces the manual runbook ritual
// (add-repo → hand-rebuild bundle.json → inline kubeseal → commit) with a single
// idempotent, offline, self-verifying step:
//
//	sealdctl admin onboard --project-id N [--repo <dir>] [--keystore <dir>] [--rotate]
//
// It mints the repo's per-repo key and APPENDS it to the keystore dir as
// <N>.key.json (never edits a shared blob), writes the correct v2 .seald/repo.yaml
// into --repo (or stdout), self-verifies the written key unwraps to the recipient
// it committed, and NO-OPS if the repo is already onboarded (existence =
// idempotence; --rotate to deliberately re-mint). It does NOT push — the operator
// reviews + commits (stays offline/tokenless; respects "commit only when asked").
//
// The cluster topology (env→cluster, cluster recipients, env_min_level) is copied
// from an existing broker registry entry (--clusters-from-registry <projects.json>,
//) or a v2/v3-era repo.yaml (--clusters-from), so a new project on existing
// clusters inherits the fleet's topology.

// onboardClusterInputs resolves the cluster topology an onboard needs into
// OnboardInputs. v4 (preferred): --clusters-from-registry <projects.json> copies
// the topology from ANY existing project entry (the fleet shares clusters). Back-
// compat: --clusters-from <repo.yaml> reads a v2/v3-era repo.yaml that still
// carries clusters/env_cluster. HumanRecip is unused for a fresh mint (the minted
// key IS the recipient) — left empty here.
// onboardClusterInputs copies the fleet's env TOPOLOGY (cluster/namespace/min_level)
// from an existing registry entry and MINTS FRESH per-(project,env) materializer
// keys for this project — so a new project never shares another project's
// materializer key. Returns the OnboardInputs (with fresh per-env recipients) + the
// env→private-identity map (to seed the out-of-band per-env Secrets).
func onboardClusterInputs(flags map[string]string, repoDir string, pid int64) (client.OnboardInputs, map[string]string, error) {
	rf := flags["clusters-from-registry"]
	if rf == "" {
		return client.OnboardInputs{}, nil, fmt.Errorf("--clusters-from-registry <projects.json> is required " +
			"(copies the fleet's env TOPOLOGY — cluster/namespace/min_level; recipients are freshly minted per project)")
	}
	data, err := os.ReadFile(rf)
	if err != nil {
		return client.OnboardInputs{}, nil, fmt.Errorf("read --clusters-from-registry %s: %w", rf, err)
	}
	reg, err := client.ParseProjectRegistry(data)
	if err != nil {
		return client.OnboardInputs{}, nil, err
	}
	// copy TOPOLOGY from any existing entry (the fleet shares clusters/namespaces),
	// then mint fresh per-env materializer keys — recipients are per-(project,env).
	for _, e := range reg {
		if len(e.Envs) == 0 {
			continue
		}
		envs, idents, err := client.MintEnvMaterializerKeys(e.Envs)
		if err != nil {
			return client.OnboardInputs{}, nil, fmt.Errorf("mint per-env keys: %w", err)
		}
		return client.OnboardInputs{ProjectID: pid, Envs: envs}, idents, nil
	}
	return client.OnboardInputs{}, nil, fmt.Errorf("--clusters-from-registry %s has no project entry with environments to copy", rf)
}

func cmdAdminOnboard(args []string) {
	flags, _ := parseFlags(args)
	pidStr := flags["project-id"]
	if pidStr == "" {
		fail("admin onboard requires --project-id N")
	}
	var pid int64
	if _, err := fmt.Sscanf(pidStr, "%d", &pid); err != nil || pid <= 0 {
		fail("admin onboard: --project-id %q must be a positive integer", pidStr)
	}

	repoDir := flags["repo"]
	if repoDir == "" {
		repoDir = "."
	}
	// The keystore is a LOCAL staging dir (never git). Default to a temp
	// dir; the private key is then delivered to the broker via --apply (kubectl
	// patch) or written out via --emit-keyfile. --keystore overrides the staging dir.
	keystoreDir := flags["keystore"]
	if keystoreDir == "" {
		td, err := os.MkdirTemp("", "seald-onboard-")
		if err != nil {
			fail("onboard: temp keystore: %v", err)
		}
		defer os.RemoveAll(td)
		keystoreDir = td
	}
	force := flags["rotate"] == "true"

	// Cluster topology source: a project's env→cluster map + cluster
	// recipients + env_min_level live in the broker registry (projects.json), NOT in
	// the now-recipient-only repo.yaml. A new project on EXISTING clusters copies the
	// fleet topology from any existing projects.json entry:
	//   --clusters-from-registry <projects.json>   (v4 — preferred)
	// A v2/v3-era repo.yaml that still carries clusters is also accepted for
	// back-compat:
	//   --clusters-from <repo.yaml>
	in, envIdentities, err := onboardClusterInputs(flags, repoDir, pid)
	if err != nil {
		fail("admin onboard: %v", err)
	}
	res, err := client.PlanOnboard(in, keystoreDir, force)
	if err != nil {
		fail("onboard: %v", err)
	}

	// self-verify: the written key unwraps to exactly the recipient we committed.
	data, err := os.ReadFile(res.KeyPath)
	if err != nil {
		fail("onboard: re-read key: %v", err)
	}
	kf, err := client.ParseKeyFile(data)
	if err != nil {
		fail("onboard: written key invalid: %v", err)
	}
	if err := kf.Verify(res.Recipient); err != nil {
		fail("onboard SELF-CHECK FAILED (key does not match its repo.yaml recipient): %v", err)
	}

	// write repo.yaml into the target repo (or stdout if --repo -).
	if repoDir == "-" {
		fmt.Print(res.RepoYAML)
	} else {
		rp := filepath.Join(repoDir, ".seald", "repo.yaml")
		if err := os.MkdirAll(filepath.Dir(rp), 0755); err != nil {
			fail("onboard: mkdir .seald: %v", err)
		}
		if err := os.WriteFile(rp, []byte(res.RepoYAML), 0644); err != nil {
			fail("onboard: write repo.yaml: %v", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", rp)
	}

	action := "reused existing key (idempotent no-op)"
	if res.Minted {
		action = "minted new key"
	}
	if force && res.Minted {
		action = "ROTATED key (new recipient)"
	}
	fmt.Fprintf(os.Stderr, "onboard project %d: %s\n  recipient: %s\n  ✓ self-verified\n",
		pid, action, res.Recipient)

	// Deliver the private key to the broker's out-of-band keystore (NEVER
	// git). --apply patches the seald-broker-keystore Secret in ns seald, adding/
	// replacing ONLY this repo's data key. --emit-keyfile writes the v2 keyfile to a
	// path (air-gapped / manual seeding). If neither, print the manual next-step.
	switch {
	case flags["apply"] == "true":
		if err := kubectlPatchKeystore(pid, data, flags["kube-context"], flags["keystore-secret"], flags["keystore-namespace"]); err != nil {
			fail("onboard --apply: %v", err)
		}
		fmt.Fprintf(os.Stderr, "  ✓ applied %s into the broker keystore Secret (out-of-band, not git)\n", client.KeyFileName(pid))
	case flags["emit-keyfile"] != "":
		out := flags["emit-keyfile"]
		if err := os.WriteFile(out, data, 0600); err != nil {
			fail("onboard --emit-keyfile: %v", err)
		}
		fmt.Fprintf(os.Stderr, "  wrote key file %s (chmod 600) — seed it into the broker keystore Secret out-of-band\n", out)
	default:
		fmt.Fprintf(os.Stderr, "next: deliver the key to the broker keystore with --apply "+
			"(kubectl patch Secret seald-broker-keystore -n seald), OR --emit-keyfile <path> for manual seeding. "+
			"Then commit ONLY the target repo's .seald/repo.yaml (the private key never goes to git).\n")
	}

	// emit the project's broker-registry entry (projects.json) too, so
	// onboarding is ONE command → TWO reviewed commits (recipient-only repo.yaml in
	// the target repo + this registry row in infra-repo), with no hand-editing of
	// projects.json. --registry-file merges+writes it (the operator commits + opens
	// the CODEOWNERS MR); otherwise it's printed for review.
	entry, rerr := client.RegistryEntryFor(in, res.Recipient)
	if rerr != nil {
		fail("onboard: build registry entry: %v", rerr)
	}
	if rf := flags["registry-file"]; rf != "" {
		if err := mergeRegistryEntry(rf, entry); err != nil {
			fail("onboard --registry-file: %v", err)
		}
		fmt.Fprintf(os.Stderr, "  ✓ merged project %d into %s — commit it (CODEOWNERS MR) so ArgoCD syncs the broker\n", pid, rf)
	} else {
		out, _ := entry.MarshalJSON2()
		fmt.Printf("\n# broker registry entry — merge into infra-repo apps/seald/manifests/registry/projects.json\n# (or re-run with --registry-file <path> to merge+write it):\n%s\n", out)
	}

	// emit the freshly-minted PER-ENV materializer PRIVATE identities. Each
	// must be seeded out-of-band into gitseal-materializer-<project>-<env> in ns
	// seald (never git) + Shamir-escrowed for DR. These are the per-(project,env)
	// keys the env-materializers decrypt with — distinct from every other project's.
	if len(envIdentities) > 0 {
		fmt.Fprintf(os.Stderr, "\n⚠ seed these PER-ENV materializer identities out-of-band (Secret gitseal-materializer-%d-<env> in ns seald; NEVER git) + escrow them:\n", pid)
		for _, env := range sortedKeysOf(envIdentities) {
			fmt.Printf("# gitseal-materializer-%d-%s  (recipient %s)\n%s\n", pid, env, in.Envs[env].Recipient, envIdentities[env])
		}
	}
}

// mergeRegistryEntry merges a single-project registry entry into the git-tracked
// projects.json at path (creating it if absent), preserving every other project's
// rows, and writes it back for the operator to commit.
func mergeRegistryEntry(path string, entry client.ProjectRegistry) error {
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	reg, err := client.ParseProjectRegistry(data)
	if err != nil {
		return err
	}
	for pub, e := range entry {
		reg[pub] = e
	}
	out, err := reg.MarshalJSON2()
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o644)
}

// kubectlPatchKeystore adds/replaces ONE data key (<pid>.key.json) in the broker's
// out-of-band keystore Secret via a strategic-merge patch, without touching any
// other repo's key. Shells out to kubectl (no client-go — consistent with the
// materializer's kill-path discipline). Defaults: Secret seald-broker-keystore, ns
// seald. The base64 of the keyfile bytes is the data value.
func kubectlPatchKeystore(pid int64, keyfile []byte, kubeContext, secret, namespace string) error {
	if secret == "" {
		secret = "seald-broker-keystore"
	}
	if namespace == "" {
		namespace = "seald"
	}
	patch := map[string]any{"data": map[string]string{
		client.KeyFileName(pid): base64.StdEncoding.EncodeToString(keyfile),
	}}
	pj, _ := json.Marshal(patch)
	argv := []string{}
	if kubeContext != "" {
		argv = append(argv, "--context", kubeContext)
	}
	patchArgs := append(append([]string(nil), argv...), "-n", namespace, "patch", "secret", secret,
		"--type", "merge", "-p", string(pj))
	cmd := exec.Command("kubectl", patchArgs...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	// Readback (review should-fix #3): confirm the key actually LANDED — a merge
	// patch can exit 0 under a read-only RBAC / server-side quirk without persisting.
	// Read the data key back and compare to what we sent (fail-closed on mismatch).
	getArgs := append(append([]string(nil), argv...), "-n", namespace, "get", "secret", secret,
		"-o", "jsonpath={.data."+strings.ReplaceAll(client.KeyFileName(pid), ".", "\\.")+"}")
	out, err := exec.Command("kubectl", getArgs...).Output()
	if err != nil {
		return fmt.Errorf("patch readback: %w", err)
	}
	if strings.TrimSpace(string(out)) != base64.StdEncoding.EncodeToString(keyfile) {
		return fmt.Errorf("patch readback MISMATCH — the key did not land in Secret %s/%s (RBAC? conflict?)", namespace, secret)
	}
	return nil
}

// cmdVerifyKeys is the offline key-store integrity gate (CI / pre-commit):
//
//	sealdctl verify-keys --dir <keystore>
//
// It loads every <pid>.key.json in the directory and unwraps each offline; any
// file that fails to parse/unwrap is reported and the command exits non-zero, so
// a malformed key never reaches the broker (shift-left the validation that today
// is deferred to broker boot). It needs no token, no broker, no network.
func cmdVerifyKeys(args []string) {
	flags, _ := parseFlags(args)
	dir := flags["dir"]
	if dir == "" {
		dir = filepath.Join("keys")
	}
	ks, skipped, err := client.LoadKeyDir(dir)
	if err != nil {
		fail("verify-keys: %v", err)
	}
	for _, s := range skipped {
		fmt.Fprintf(os.Stderr, "✗ %s\n", s)
	}
	if len(skipped) > 0 {
		fail("verify-keys FAILED: %d invalid key file(s) in %s", len(skipped), dir)
	}
	fmt.Printf("verify-keys OK: %d valid key file(s) in %s\n", len(ks.Identities), dir)
}

// cmdTree prints a per-env key + signer tree for one service (or all .sealed/*),
// with NO ciphertext blobs (ergonomics):
//
//	sealdctl tree [--svc auth]
func cmdTree(args []string) {
	flags, _ := parseFlags(args)
	var paths []string
	if svc := flags["svc"]; svc != "" {
		paths = []string{filepath.Join(".sealed", svc+".app.json")}
	} else {
		p, _ := filepath.Glob(filepath.Join(".sealed", "*.app.json"))
		sort.Strings(p)
		paths = p
	}
	if len(paths) == 0 {
		fail("no bundles found under .sealed/*.app.json")
	}
	for _, p := range paths {
		b, err := client.LoadBundle(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ %s: %v\n", p, err)
			continue
		}
		svc := strings.TrimSuffix(filepath.Base(p), ".app.json")
		fmt.Print(client.RenderTree(svc, b))
	}
}

// cmdMigrateV3 transitions v2 bundles to the normalized, signed v3 format
// in place. It is a STRUCTURAL transform + signature — it never
// decrypts, so a migrated bundle materializes to the identical plaintext:
//
//	sealdctl migrate-v3 --svc auth     # one service
//	sealdctl migrate-v3 --all          # every .sealed/*.app.json
//
// project_id comes from .seald/repo.yaml; the signer is the caller's SSH key
// (agent via SSH_AUTH_SOCK, or --key / SEALD_SSH_KEY). The signer must be a
// registered gitseal user with live level >= each env's min for the result to
// pass `verify --authz` — but signing itself is offline (no broker call).
func cmdMigrateV3(args []string) {
	flags, _ := parseFlags(args)

	rc, err := client.LoadRepoConfig(".")
	if err != nil {
		fail("migrate-v3: read .seald/repo.yaml: %v", err)
	}
	if rc.ProjectID <= 0 {
		fail("migrate-v3: .seald/repo.yaml has no project_id")
	}

	var paths []string
	if svc := flags["svc"]; svc != "" {
		paths = []string{filepath.Join(".sealed", svc+".app.json")}
	} else if flags["all"] == "true" {
		p, _ := filepath.Glob(filepath.Join(".sealed", "*.app.json"))
		sort.Strings(p)
		paths = p
	} else {
		fail("migrate-v3 requires --svc NAME or --all")
	}
	if len(paths) == 0 {
		fail("no bundles found under .sealed/*.app.json")
	}

	signer, err := client.LoadSSHSigner(env("SEALD_SSH_KEY", flags["key"]), "")
	if err != nil {
		fail("migrate-v3: no ssh signer (start ssh-agent or pass --key): %v", err)
	}

	migrated, skipped, failed := 0, 0, 0
	for _, p := range paths {
		res, err := client.MigrateBundleToV3(p, rc.ProjectID, signer)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ %s: %v\n", p, err)
			failed++
			continue
		}
		if res.FromVersion == client.BundleVersionV3 {
			skipped++ // already v3 — re-signed
		} else {
			migrated++
		}
		fmt.Printf("✓ %s: %s → v3, signed %v by %s\n",
			p, res.FromVersion, res.EnvsSigned, res.Fingerprint)
	}
	fmt.Printf("migrate-v3: %d migrated, %d re-signed(v3), %d failed → project %d\n",
		migrated, skipped, failed, rc.ProjectID)
	if failed > 0 {
		os.Exit(1)
	}
}

// cmdMigrateV4 re-seals v2/v3 bundles to v4, where the project PUBKEY
// (recipient) is the embedded anti-splice discriminator instead of the numeric
// project_id — the last step in collapsing .seald/repo.yaml to `recipient:` only:
//
//	sealdctl migrate-v4 --human-key <path> --svc auth
//	sealdctl migrate-v4 --human-key <path> --all
//
// Unlike migrate-v3 (offline struct transform), this DECRYPTS + RE-ENCRYPTS, so it
// needs the repo's HUMAN PRIVATE KEY (--human-key file, or SEALD_HUMAN_KEY; "-" =
// stdin) — extract it from the broker's out-of-band keystore Secret for the
// migration, then discard it. clusters/env_cluster/recipient come from repo.yaml;
// the SSH signer (agent / SEALD_SSH_KEY / --key) re-signs each section. Plaintext
// is preserved; per-env cluster isolation is preserved.
func cmdMigrateV4(args []string) {
	flags, _ := parseFlags(args)

	rc, err := resolveRC(".")
	if err != nil {
		fail("migrate-v4: resolve repo config: %v", err)
	}
	if rc.Recipient == "" {
		fail("migrate-v4: .seald/repo.yaml has no recipient")
	}
	if len(rc.Clusters) == 0 || len(rc.EnvCluster) == 0 {
		fail("migrate-v4: need clusters + env_cluster (from repo.yaml or the registry snapshot) to pick each env's recipient")
	}

	humanKey := readHumanKey(flags)
	if humanKey == "" {
		fail("migrate-v4 requires --human-key <path> (the repo private identity; extract from the broker keystore Secret) or SEALD_HUMAN_KEY")
	}

	var paths []string
	if svc := flags["svc"]; svc != "" {
		paths = []string{filepath.Join(".sealed", svc+".app.json")}
	} else if flags["all"] == "true" {
		p, _ := filepath.Glob(filepath.Join(".sealed", "*.app.json"))
		sort.Strings(p)
		paths = p
	} else {
		fail("migrate-v4 requires --svc NAME or --all")
	}
	if len(paths) == 0 {
		fail("no bundles found under .sealed/*.app.json")
	}

	signer, err := client.LoadSSHSigner(env("SEALD_SSH_KEY", flags["key"]), "")
	if err != nil {
		fail("migrate-v4: no ssh signer (start ssh-agent or pass --key): %v", err)
	}

	migrated, failed := 0, 0
	for _, p := range paths {
		res, err := client.MigrateBundleToV4(p, humanKey, rc.Recipient, rc.Clusters, rc.EnvCluster, signer)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ %s: %v\n", p, err)
			failed++
			continue
		}
		migrated++
		fmt.Printf("✓ %s: %s → v4, re-sealed+signed %v by %s\n", p, res.FromVersion, res.EnvsSigned, res.Fingerprint)
	}
	fmt.Printf("migrate-v4: %d migrated, %d failed → recipient %s\n", migrated, failed, rc.Recipient)
	if failed > 0 {
		os.Exit(1)
	}
}

// cmdMigrateEnv re-seals v4 bundles from per-CLUSTER recipients to per-ENV
// recipients, giving each environment its own crypto boundary:
//
//	sealdctl migrate-env --human-key <path> --svc auth   # one service
//	sealdctl migrate-env --human-key <path> --all        # every bundle
//
// The per-env recipients come from the registry snapshot (each env's
// env.recipient), resolved via the broker. Like migrate-v4 it decrypts + re-encrypts
// (needs the human/project key, out-of-band), preserving plaintext; prod and preprod
// end up on DIFFERENT keys so a prod section can't be opened by the preprod key.
func cmdMigrateEnv(args []string) {
	flags, _ := parseFlags(args)
	rc, err := resolveRC(".")
	if err != nil {
		fail("migrate-env: resolve repo config: %v", err)
	}
	if rc.Recipient == "" {
		fail("migrate-env: .seald/repo.yaml has no recipient")
	}
	if len(rc.EnvRecipient) == 0 {
		fail("migrate-env: the registry has no per-env recipients — run `admin env set --recipient …` for each env first")
	}
	humanKey := readHumanKey(flags)
	if humanKey == "" {
		fail("migrate-env requires --human-key <path> (the repo private identity) or SEALD_HUMAN_KEY")
	}
	var paths []string
	if svc := flags["svc"]; svc != "" {
		paths = []string{filepath.Join(".sealed", svc+".app.json")}
	} else if flags["all"] == "true" {
		p, _ := filepath.Glob(filepath.Join(".sealed", "*.app.json"))
		sort.Strings(p)
		paths = p
	} else {
		fail("migrate-env requires --svc NAME or --all")
	}
	if len(paths) == 0 {
		fail("no bundles found under .sealed/*.app.json")
	}
	signer, err := client.LoadSSHSigner(env("SEALD_SSH_KEY", flags["key"]), "")
	if err != nil {
		fail("migrate-env: no ssh signer (start ssh-agent or pass --key): %v", err)
	}

	migrated, failed := 0, 0
	for _, p := range paths {
		res, err := client.ReSealToEnvRecipients(p, humanKey, rc.Recipient, rc.EnvRecipient, signer)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ %s: %v\n", p, err)
			failed++
			continue
		}
		migrated++
		fmt.Printf("✓ %s: re-sealed to per-env recipients %v by %s\n", p, res.EnvsSigned, res.Fingerprint)
	}
	fmt.Printf("migrate-env: %d migrated, %d failed\n", migrated, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

// readHumanKey resolves the repo human private identity for migrate-v4 from
// --human-key <path> (or "-" for stdin) or $SEALD_HUMAN_KEY. Returns "" if none.
func readHumanKey(flags map[string]string) string {
	if v := env("SEALD_HUMAN_KEY", ""); v != "" {
		return strings.TrimSpace(v)
	}
	path := flags["human-key"]
	if path == "" {
		return ""
	}
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		fail("read --human-key %s: %v", path, err)
	}
	return strings.TrimSpace(string(data))
}

// cmdEnv is the developer's environment inspector:
//
//	sealdctl env list     # this repo's envs → cluster, required level, can-you-seal
//
// It resolves the repo's operational config from the broker registry snapshot
// (keyed by the repo recipient, cached/offline), then best-effort resolves the
// caller's live project level to fill the can-seal column. No secrets are read;
// this is the read-side twin of `admin env set`.
func cmdEnv(args []string) {
	if len(args) == 0 || args[0] != "list" {
		fail("usage: sealdctl env list")
	}
	rc, err := resolveRC(".")
	if err != nil {
		fail("env: %v", err)
	}
	// best-effort caller level (unknown → -1, rendered "?"): a missing token or an
	// unreachable GitLab must NOT break `env list` — it still shows the topology.
	level := -1
	host := env("SEALD_HOST", defaultHost)
	if token, _, terr := client.ResolvePAT(host, ""); terr == nil && rc.ProjectID > 0 {
		if lvl, lerr := client.CallerProjectLevel(host, token, rc.ProjectID); lerr == nil {
			level = lvl
		}
	}
	fmt.Print(client.RenderEnvList(rc, level))
}

// cmdAdminCombine reconstructs the seald-root PRIVATE identity ("AGE-SECRET-KEY-1…")
// from >= threshold Shamir shares and writes it to STDOUT (and NOWHERE else) so an
// operator can seed the in-cluster materializer Secret, e.g.:
//
//	sealdctl admin combine --share <s1> --share <s2> > identity
//	sealdctl admin combine --shares-file custodian-shares.txt > identity
//	kubectl create secret generic gitseal-materializer -n seald --from-file=identity=identity
//
// Shares come from EITHER repeated --share flags OR a --shares-file (one base64
// share per line; blank and #-comment lines ignored) — or both, merged. parseFlags
// keeps only the last value of a repeated flag, so every --share is scanned from the
// raw args (same pattern as collectEnvFileFlags for --env-file).
//
// SECURITY: the emitted identity is the seald-root PRIVATE key. It is printed to
// STDOUT ONLY — never logged, never echoed elsewhere. Pipe it straight into a file
// with 0600 perms (or directly into kubectl) and shred it after seeding; NEVER commit
// it. On < threshold shares shamir.Combine fails and the error is surfaced (fail-closed).
//
// --verify additionally derives the public recipient (age1…) from the reconstructed
// identity and prints it to STDERR (so it does NOT pollute the piped identity on
// stdout), letting the operator confirm it matches the committed repo.yaml clusters
// entry BEFORE seeding.
func cmdAdminCombine(args []string) {
	flags, _ := parseFlags(args)

	shares := collectShareFlags(args)
	if sf := flags["shares-file"]; sf != "" {
		fileShares, err := readSharesFile(sf)
		if err != nil {
			fail("%v", err)
		}
		shares = append(shares, fileShares...)
	}
	if len(shares) == 0 {
		fail("admin combine requires shares: --share S (repeatable) and/or --shares-file PATH\n" +
			"  SECURITY: this emits the seald-root PRIVATE key to stdout — pipe to a\n" +
			"  0600 file (or kubectl) and shred it; NEVER commit it. e.g.\n" +
			"    sealdctl admin combine --share S1 --share S2 --expect <recipient> > identity && chmod 600 identity\n" +
			"  --expect <recipient> fails closed (emits NOTHING) if the reconstruction\n" +
			"  doesn't match. To REHEARSE without emitting a key: sealdctl admin escrow-check.")
	}

	identity, err := client.CombineShares(shares)
	if err != nil {
		fail("%v", err)
	}

	// --verify: derive the public recipient from the reconstructed identity and
	// print it to STDERR so the operator can match it against repo.yaml before
	// seeding. Kept off stdout so `... > identity` stays a clean private-key file.
	//
	// --expect <recipient>: FAIL CLOSED if the derived recipient does not equal the
	// expected one (typically the cluster's committed repo.yaml `clusters` entry).
	// This turns "shares reconstructed the wrong/corrupt key" into a hard error at
	// combine time — before the private key is written to stdout / seeded — rather
	// than a silent DR-time surprise. Implies --verify.
	expect := flags["expect"]
	if flags["verify"] == "true" || expect != "" {
		id, err := age.ParseX25519Identity(identity)
		if err != nil {
			fail("reconstructed identity did not parse as an age X25519 key: %v", err)
		}
		got := id.Recipient().String()
		fmt.Fprintf(os.Stderr, "recipient: %s\n", got)
		if expect != "" && got != expect {
			fail("combine --expect MISMATCH: reconstructed %s != expected %s\n"+
				"  (wrong shares, a corrupt share, or the wrong cluster) — NOT emitting the private key", got, expect)
		}
	}

	// The PRIVATE key → stdout and NOTHING else, so a redirect yields a clean file.
	fmt.Println(identity)
}

// collectShareFlags scans raw args for EVERY `--share <value>` occurrence (both
// `--share x` and `--share=x` forms), returning each value. Like collectEnvFileFlags,
// this exists because parseFlags keeps only the LAST value of a repeated flag, but
// --share is intentionally multi-valued (one per custodian).
func collectShareFlags(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--share":
			if i+1 < len(args) {
				out = append(out, args[i+1])
				i++
			}
		case strings.HasPrefix(a, "--share="):
			out = append(out, strings.TrimPrefix(a, "--share="))
		}
	}
	return out
}

// readSharesFile reads one base64 share per line from path. Blank lines and lines
// whose first non-space rune is '#' are ignored (operator convenience — the file may
// carry comments). Surrounding whitespace on each share is trimmed.
func readSharesFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --shares-file %s: %w", path, err)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--shares-file %s contained no shares (non-empty, non-# lines)", path)
	}
	return out, nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sealdctl <seal|reseal|unseal|verify|verify-keys|materialize|doctor|admin> [flags]")
	fmt.Fprintln(os.Stderr, "  admin: <onboard|add-repo|gen-root|combine>")
}

// cmdVerify runs the decrypt-free per-cluster recipient audit (mandatory gate #1)
// over every .sealed/*.app.json v2 bundle in the repo:
//
//	sealdctl verify [--strict]
//
// It loads .seald/repo.yaml (the cluster registry), globs the bundles, and runs
// client.VerifyBundle on each. Hard violations print to stderr as ✗ and a
// non-empty set exits non-zero (so CI reds). Advisory warnings print as ⚠ but
// do NOT fail the run on their own. A v1 (un-migrated) bundle is a warning in
// the default (migration-window) mode — verify still exits 0 so wiring this
// into CI does not red the pipeline on bundles that have not yet been resealed
// to v2. With --strict, a v1 bundle is a hard failure instead. On success it
// prints "verify OK: N bundle(s)" (plus a count of any warnings). No private
// key, no broker, no network — this is the cheap early tripwire before the
// materialize-time cross-check (gate #2). See client.VerifyBundle for the L1
// residual it cannot catch.
func cmdVerify(args []string) {
	flags, _ := parseFlags(args)
	if flags["authz"] == "true" {
		cmdVerifyAuthz(flags)
		return
	}
	strict := flags["strict"] == "true"

	rc, err := client.LoadRepoConfig(".")
	if err != nil {
		fail("%v", err)
	}

	// Same repo-root convention as seal/unseal: operate relative to CWD.
	paths, err := filepath.Glob(filepath.Join(".sealed", "*.app.json"))
	if err != nil {
		fail("glob .sealed: %v", err)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		fail("no bundles found under .sealed/*.app.json")
	}

	viols, warns := 0, 0
	for _, p := range paths {
		b, err := client.LoadBundle(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ %s: %v\n", p, err)
			viols++
			continue
		}
		res := client.VerifyBundle(b, rc, strict)
		for _, w := range res.Warnings {
			fmt.Fprintf(os.Stderr, "⚠  %s: %s\n", p, w)
		}
		warns += len(res.Warnings)
		for _, v := range res.Violations {
			fmt.Fprintf(os.Stderr, "✗ %s: %s\n", p, v)
		}
		viols += len(res.Violations)
	}

	if viols > 0 {
		fail("verify FAILED: %d violation(s) across %d bundle(s)", viols, len(paths))
	}
	if warns > 0 {
		fmt.Printf("verify OK: %d bundle(s), %d warning(s) (see ⚠ above)\n", len(paths), warns)
		return
	}
	fmt.Printf("verify OK: %d bundle(s)\n", len(paths))
}

// cmdMaterialize is the in-cluster Secret materializer (Phase 4). It is the
// PreSync-hook entrypoint: it reads the per-Job wiring from the environment
// (GITSEAL_ENV / GITSEAL_NAMESPACE / GITSEAL_CLUSTER) + the mounted cluster
// identity (--identity, default /etc/gitseal/identity), globs .sealed/*.app.json,
// and for EACH bundle calls client.BuildSecretForBundle — which fail-closed
// cross-checks the section's cluster against GITSEAL_CLUSTER BEFORE decrypting
// (mandatory gate #2).
//
//	sealdctl materialize --emit-yaml            # render Secrets to stdout, NO cluster contact
//	sealdctl materialize [--identity PATH]      # kubectl apply + prune orphans (default)
//	sealdctl materialize --dir PATH             # read bundles from PATH/.sealed (else cwd)
//
// --dir <path> makes the command read bundles from <path>/.sealed/*.app.json
// instead of ./.sealed/*.app.json. This unblocks running materialize inside a
// k8s Job pod that git-clones the repo to a mounted path (rather than execing
// from the repo root). When --dir is absent behavior is byte-identical to the
// original cwd-relative glob. materialize does NOT read .seald/repo.yaml (it
// works purely off the bundles + GITSEAL_* env + the mounted identity), so the
// bundle glob is the only path --dir needs to redirect; --identity is resolved
// verbatim (default /etc/gitseal/identity, an absolute path) and is unaffected.
//
// ON ANY ERROR the whole run aborts non-zero and NOTHING is applied — the build
// of every Secret completes (all-or-nothing) BEFORE any kubectl apply, so a
// wrong-cluster/decrypt failure blocks the sync rather than shipping a partial
// set. --emit-yaml prints each RenderSecretYAML separated by "---" (for the
// byte-equivalence harness); default mode kubectl-applies each manifest then
// prunes any managed-by=gitseal-materializer Secret in the namespace not in the
// current rendered set. kubectl is shelled out to (os/exec) — no client-go in the
// kill-path (lessons.md L7).
func cmdMaterialize(args []string) {
	flags, _ := parseFlags(args)
	emitYAML := flags["emit-yaml"] == "true"

	envName := os.Getenv("GITSEAL_ENV")
	namespace := os.Getenv("GITSEAL_NAMESPACE")
	cluster := os.Getenv("GITSEAL_CLUSTER")
	if envName == "" || cluster == "" {
		fail("materialize requires GITSEAL_ENV and GITSEAL_CLUSTER in the environment")
	}
	if !emitYAML && namespace == "" {
		fail("materialize (apply mode) requires GITSEAL_NAMESPACE in the environment")
	}

	// Identity is only needed to decrypt; --emit-yaml still decrypts (it renders
	// the real, resolved Secret), so the identity is required in both modes.
	identPath := flags["identity"]
	if identPath == "" {
		identPath = "/etc/gitseal/identity"
	}
	identity, err := os.ReadFile(identPath)
	if err != nil {
		fail("read identity %s: %v", identPath, err)
	}
	identity = []byte(strings.TrimSpace(string(identity)))

	// --dir redirects the bundle glob to <dir>/.sealed (default: cwd → .sealed).
	dir := flags["dir"]
	sealedGlob := filepath.Join(".sealed", "*.app.json")
	if dir != "" {
		sealedGlob = filepath.Join(dir, ".sealed", "*.app.json")
	}
	paths, err := filepath.Glob(sealedGlob)
	if err != nil {
		fail("glob %s: %v", sealedGlob, err)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		fail("no bundles found under %s", sealedGlob)
	}

	// Anti-splice discriminator(s) to re-assert against each AEAD envelope, resolved
	// from the env or the repo's .seald/repo.yaml (git-cloned alongside .sealed under
	// --dir) — NEVER a live broker call, so the materializer stays registry-INDEPENDENT
	// (invariant #3). v1-v3 use the numeric project_id; v4 uses the project
	// pubkey (recipient). Resolve BOTH so a repo mid-migration (mixed v3+v4 bundles)
	// materializes either shape; the materializer picks the right one per bundle.
	var projectID int64
	var recipient string
	if v := os.Getenv("GITSEAL_PROJECT_ID"); v != "" {
		fmt.Sscanf(v, "%d", &projectID)
	}
	recipient = os.Getenv("GITSEAL_RECIPIENT")
	if projectID == 0 || recipient == "" {
		root := "."
		if dir != "" {
			root = dir
		}
		if rc, e := client.LoadRepoConfig(root); e == nil {
			if projectID == 0 {
				projectID = rc.ProjectID
			}
			if recipient == "" {
				recipient = rc.Recipient
			}
		}
	}

	// PHASE 1 — build every Secret (all-or-nothing) BEFORE touching the cluster.
	// Any error here (missing env, cluster cross-check mismatch, decrypt failure)
	// aborts the whole run non-zero with NOTHING applied — mandatory gate #2.
	secretPrefix := os.Getenv("GITSEAL_SECRET_PREFIX") // tenant discriminator; "" → "<svc>-app"
	in := client.MaterializeInput{Env: envName, Namespace: namespace, Cluster: cluster, Identity: identity, ProjectID: projectID, Recipient: recipient, SecretPrefix: secretPrefix}
	built := make([]*client.K8sSecret, 0, len(paths))
	for _, p := range paths {
		b, err := client.LoadBundle(p)
		if err != nil {
			fail("%s: %v", p, err)
		}
		svc := client.ServiceFromBundlePath(p)
		sec, err := client.BuildSecretForBundle(b, svc, in)
		if err != nil {
			fail("%v", err)
		}
		built = append(built, sec)
	}

	// PHASE 2 — emit or apply.
	if emitYAML {
		for i, sec := range built {
			if i > 0 {
				fmt.Println("---")
			}
			os.Stdout.Write(client.RenderSecretYAML(sec))
		}
		return
	}

	// apply each manifest via `kubectl apply -f -`.
	for _, sec := range built {
		if err := kubectlApply(client.RenderSecretYAML(sec)); err != nil {
			fail("kubectl apply %s: %v", sec.Name, err)
		}
	}

	// prune: any managed-by=gitseal-materializer Secret in the namespace NOT in
	// the current rendered set is an orphan → delete it (mirrors ArgoCD prune).
	want := map[string]bool{}
	for _, sec := range built {
		want[sec.Name] = true
	}
	live, err := kubectlManagedSecrets(namespace)
	if err != nil {
		fail("kubectl list managed secrets: %v", err)
	}
	for _, name := range live {
		if want[name] {
			continue
		}
		if err := kubectlDeleteSecret(namespace, name); err != nil {
			fail("kubectl delete secret %s: %v", name, err)
		}
		fmt.Fprintf(os.Stderr, "pruned orphan Secret %s/%s\n", namespace, name)
	}
	fmt.Printf("materialized %d Secret(s) into namespace %s (env %s, cluster %s)\n", len(built), namespace, envName, cluster)
}

// kubectlApply pipes a rendered manifest to `kubectl apply -f -`.
func kubectlApply(manifest []byte) error {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(string(manifest))
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr // apply chatter → stderr (keep stdout clean)
	return cmd.Run()
}

// kubectlManagedSecrets returns the names of Secrets in ns labelled
// managed-by=gitseal-materializer (the materializer's own prune candidates).
func kubectlManagedSecrets(namespace string) ([]string, error) {
	cmd := exec.Command("kubectl", "get", "secret",
		"-n", namespace,
		"-l", client.ManagedByLabelKey+"="+client.ManagedByLabelValue,
		"-o", "name")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// `-o name` prints "secret/<name>".
		names = append(names, strings.TrimPrefix(line, "secret/"))
	}
	return names, nil
}

// kubectlDeleteSecret deletes one Secret by name in ns.
func kubectlDeleteSecret(namespace, name string) error {
	cmd := exec.Command("kubectl", "delete", "secret", name, "-n", namespace)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "sealdctl: "+format+"\n", a...)
	os.Exit(1)
}

// flag parsing kept deliberately tiny (no cobra dep): --name X, --value Y,
// --stdin, --export, and "-- cmd args..." for inject mode.
//
// Three flag forms are accepted (last-wins on repeats):
//
//	--key=value  → flags["key"]="value"  (split on the FIRST '='; value may contain '=')
//	--key value  → flags["key"]="value"  (space form, when the next arg is not a flag)
//	--key        → flags["key"]="true"   (bool, when the next arg is a flag or absent)
//
// A bare "--" terminates flags: everything after it is returned as rest (inject mode).
// The `=` form is required by the in-cluster materializer hook, which passes
// `materialize --dir=/repo` — without it the key was parsed literally as "dir=/repo"
// and --dir resolved empty ("no bundles found"). Note the multi-valued scanners
// collectShareFlags / collectEnvFileFlags parse os.Args directly (parseFlags is
// last-wins single-value) and already accept both `--flag v` and `--flag=v`.
func parseFlags(args []string) (flags map[string]string, rest []string) {
	flags = map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			rest = args[i+1:]
			break
		}
		if strings.HasPrefix(a, "--") {
			body := strings.TrimPrefix(a, "--")
			// --key=value: split on the FIRST '=' so the value may itself contain '='.
			if k, v, ok := strings.Cut(body, "="); ok {
				flags[k] = v
				continue
			}
			// --key value (space form) when the next arg isn't a flag; else bool --key.
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") && args[i+1] != "--" {
				flags[body] = args[i+1]
				i++
			} else {
				flags[body] = "true"
			}
		}
	}
	return
}

func cmdSeal(args []string) {
	flags, _ := parseFlags(args)
	rc, err := resolveRC(".")
	if err != nil {
		fail("%v", err)
	}

	// v2 authoring mode: `--svc NAME --from base.env [--env-file env=override.env ...]`.
	// Fans a single base.env (+ per-env overrides) out to one v2 bundle
	// .sealed/<svc>.app.json, sealing each env's resolved values to
	// [human, that env's cluster] via SealBundleV2. Selected by the presence of
	// --svc; the flat v1 --from path below is untouched when --svc is absent.
	if flags["svc"] != "" {
		cmdSealV2(args, flags, rc, false)
		return
	}

	// --from FILE: bulk-seal a whole source file (env/json/yaml) into a bundle.
	if from := flags["from"]; from != "" {
		cmdSealFrom(flags, rc, from)
		return
	}

	name := flags["name"]
	if name == "" {
		fail("seal requires --name (or --from FILE for a whole bundle)")
	}
	var value []byte
	switch {
	case flags["value"] != "":
		value = []byte(flags["value"])
	case flags["stdin"] == "true":
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, e := os.Stdin.Read(buf)
			b.Write(buf[:n])
			if e != nil {
				break
			}
		}
		value = []byte(strings.TrimRight(b.String(), "\n"))
	default:
		fail("seal requires --value V or --stdin")
	}
	if err := client.SealToFile(".", rc, name, value); err != nil {
		fail("%v", err)
	}
	fmt.Printf("sealed .sealed/%s.json (project %d)\n", name, rc.ProjectID)
}

// cmdSealFrom handles `seal --from prod.env --level 40 --out .sealed/prod.json
// [--merge] [--prune] [--emit gitseal|k8s-sealedsecret|both]`.
func cmdSealFrom(flags map[string]string, rc *client.RepoConfig, from string) {
	level := rc.MinAccessLevelOrDefault()
	if v := flags["level"]; v != "" {
		fmt.Sscanf(v, "%d", &level)
	}
	// COURTESY check (advisory, not enforcement — real gate is GitLab merge
	// controls on the bundle path). Warn if sealing a high-level
	// bundle while not Maintainer+.
	if level >= 40 {
		if token, _, err := client.ResolvePAT(env("SEALD_HOST", defaultHost), ""); err == nil {
			ok, _ := client.CallerHasLevel(env("SEALD_HOST", defaultHost), token, rc.ProjectID, level)
			if !ok {
				fmt.Fprintf(os.Stderr, "⚠  warning: you don't appear to be access-level %d+ on this project.\n", level)
				fmt.Fprintf(os.Stderr, "   Sealing still works offline, but only a Maintainer-approved MR can\n")
				fmt.Fprintf(os.Stderr, "   merge changes to a level-%d bundle (enforced by GitLab merge controls).\n", level)
			}
		}
	}

	srcFormat := flags["in-format"]
	if srcFormat == "" {
		srcFormat = client.FormatFromPath(from)
	}
	data, err := os.ReadFile(from)
	if err != nil {
		fail("read --from: %v", err)
	}
	secrets, err := client.ParseSource(data, srcFormat)
	if err != nil {
		fail("%v", err)
	}
	if len(secrets) == 0 {
		fail("no secrets parsed from %s (format %s)", from, srcFormat)
	}

	out := flags["out"]
	if out == "" {
		// default: .sealed/<basename-without-ext>.json
		base := filepath.Base(from)
		base = strings.TrimSuffix(base, filepath.Ext(base))
		out = filepath.Join(".sealed", base+".json")
	}
	if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
		fail("%v", err)
	}

	merge := flags["merge"] == "true"
	prune := flags["prune"] == "true"
	diff, err := client.SealBundle(out, rc.Recipient, rc.ProjectID, level, secrets, merge, prune)
	if err != nil {
		fail("%v", err)
	}

	// print the name-level diff
	fmt.Printf("sealed %d secret(s) → %s (project %d, level %d)\n", len(secrets), out, rc.ProjectID, level)
	for _, n := range sortedCopy(diff.Added) {
		fmt.Printf("  + %s\n", n)
	}
	for _, n := range sortedCopy(diff.Removed) {
		fmt.Printf("  - %s\n", n)
	}
	for _, n := range sortedCopy(diff.Kept) {
		fmt.Printf("    %s (kept)\n", n)
	}
	fmt.Fprintf(os.Stderr, "note: values can't be diffed (sealing is non-deterministic + offline).\n")

	// --emit: also render a bitnami SealedSecret for the ArgoCD/pod path.
	emit := flags["emit"]
	if emit == "k8s-sealedsecret" || emit == "both" {
		fmt.Fprintf(os.Stderr, "\n--emit %s: the ArgoCD/pod path uses bitnami SealedSecrets, NOT gitseal\n", emit)
		fmt.Fprintf(os.Stderr, "(gitseal blobs are human-only; a pod has no GitLab membership).\n")
		fmt.Fprintf(os.Stderr, "Render one from the SAME source with kubeseal:\n")
		ns := flags["k8s-namespace"]
		if ns == "" {
			ns = "<namespace>"
		}
		secName := flags["k8s-name"]
		if secName == "" {
			secName = strings.TrimSuffix(filepath.Base(from), filepath.Ext(from))
		}
		fmt.Fprintf(os.Stderr, "  kubectl create secret generic %s -n %s \\\n", secName, ns)
		fmt.Fprintf(os.Stderr, "    --from-env-file=%s --dry-run=client -o yaml \\\n", from)
		fmt.Fprintf(os.Stderr, "    | kubeseal --format yaml > %s.sealedsecret.yaml\n", secName)
	}
}

// cmdSealV2 implements the v2 per-env fan-out authoring path shared by
// `seal --svc` and `reseal --svc` (reseal just labels output; the machinery is
// identical — the no-nonce-churn carry-over inside SealBundleV2 makes a reseal a
// minimal-diff operation). It reads the base source (--from), collects every
// repeated `--env-file env=path` override (parseFlags is last-wins single-value,
// so overrides are scanned from the raw args here), resolves base+override per
// env over rc.EnvCluster's envs, and writes .sealed/<svc>.app.json via
// SealBundleV2 (sealing each env to [human, that env's cluster]).
func cmdSealV2(args []string, flags map[string]string, rc *client.RepoConfig, reseal bool) {
	verb := "seal"
	if reseal {
		verb = "reseal"
	}
	svc := flags["svc"]
	from := flags["from"]
	if from == "" {
		fail("%s --svc requires --from BASE.env (the shared base source)", verb)
	}
	if len(rc.EnvCluster) == 0 {
		fail("%s --svc needs a v2 repo.yaml with an env_cluster map (none found)", verb)
	}

	level := rc.MinAccessLevelOrDefault()
	if v := flags["level"]; v != "" {
		fmt.Sscanf(v, "%d", &level)
	}

	// base source (env/json/yaml → KEY→val).
	base, err := parseSourceFile(from, flags["in-format"])
	if err != nil {
		fail("%v", err)
	}
	if len(base) == 0 {
		fail("no secrets parsed from base %s", from)
	}

	// per-env overrides: every `--env-file env=path` occurrence (scanned raw so
	// repeats are all captured), parsed and validated against env_cluster.
	overrides := map[string]map[string]string{}
	for _, spec := range collectEnvFileFlags(args) {
		env, path, ok := strings.Cut(spec, "=")
		if !ok || env == "" || path == "" {
			fail("--env-file must be env=path, got %q", spec)
		}
		if _, mapped := rc.EnvCluster[env]; !mapped {
			fail("--env-file env %q is not in repo.yaml env_cluster", env)
		}
		ov, err := parseSourceFile(path, "")
		if err != nil {
			fail("%v", err)
		}
		overrides[env] = ov
	}

	// Which envs does this invocation seal? Default: ALL envs the repo declares
	// (the historical full fan-out). `--env E` scopes to a SUBSET (repeatable
	// via `--env a --env b`), so a developer with write-rights to only some envs
	// can touch just those — the other env sections are preserved byte-identical
	// by SealBundleV2's carry-over. This is the authoring twin of the write-authz
	// gate: scope + gate agree, so a sub-threshold author physically cannot fan
	// a change into an env they can't write.
	envNames := sortedKeysOf(rc.EnvCluster)
	if scoped := collectEnvFlags(args); len(scoped) > 0 {
		for _, e := range scoped {
			if _, mapped := rc.EnvCluster[e]; !mapped {
				fail("--env %q is not in repo.yaml env_cluster", e)
			}
		}
		envNames = sortedCopy(scoped)
	}
	resolved := client.ResolveEnvs(base, overrides, envNames)

	out := filepath.Join(".sealed", svc+".app.json")
	if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
		fail("%v", err)
	}

	// v4 (current) vs legacy v3 routing. A v4 repo carries per-env
	// recipients (from the registry snapshot) and NO legacy cluster map;
	// its .seald/repo.yaml is `recipient:` only, so there is no numeric project_id
	// to embed. Seal such a repo DIRECTLY as v4 (SealMultiV4 embeds the project
	// pubkey as the discriminator) — a fresh seal holds the plaintext, so this needs
	// no private key and no `migrate-v4` round-trip. Only a legacy self-contained
	// repo (clusters + numeric project_id in repo.yaml) still emits v3.
	isV4 := len(rc.EnvRecipient) > 0 && len(rc.Clusters) == 0
	var diffs map[string]client.NameDiff
	if isV4 {
		diffs, err = client.SealBundleV4(out, rc.Recipient, rc.EnvRecipient, level, resolved)
	} else {
		diffs, err = client.SealBundleV2(out, rc.Recipient, rc.Clusters, rc.EnvCluster, rc.ProjectID, level, resolved)
	}
	if err != nil {
		fail("%v", err)
	}

	// Sign each env section (attribution): who sealed it. Uses the ssh-agent
	// or SEALD_SSH_KEY. Absent a signer, warn — the CI verify --authz gate will
	// REJECT an unsigned section, so an unsigned seal won't land in prod. --no-sign
	// skips (e.g. an automated staging bump before the signer is wired). v4 signs over
	// the pubkey-bound canonical bytes; v3 over the numeric project_id.
	if flags["no-sign"] != "true" {
		if signer, serr := client.LoadSSHSigner(env("SEALD_SSH_KEY", ""), ""); serr == nil {
			var fp string
			var e error
			if isV4 {
				fp, e = client.SignBundleFileV4(out, rc.Recipient, signer)
			} else {
				fp, e = client.SignBundleFile(out, rc.ProjectID, signer)
			}
			if e != nil {
				fail("sign sections: %v", e)
			}
			fmt.Fprintf(os.Stderr, "signed all env sections as %s\n", fp)
		} else {
			fmt.Fprintf(os.Stderr, "WARNING: no SSH signer (%v) — sections are UNSIGNED; the CI write-authz gate will reject them. Start ssh-agent or set SEALD_SSH_KEY, or pass --no-sign to silence.\n", serr)
		}
	}

	fmt.Printf("%sed %s → %s (project %d, level %d, %d env section(s))\n", verb, svc, out, rc.ProjectID, level, len(resolved))
	for _, env := range envNames {
		d := diffs[env]
		fmt.Printf("  [%s → %s]\n", env, rc.EnvCluster[env])
		for _, n := range sortedCopy(d.Added) {
			fmt.Printf("    + %s\n", n)
		}
		for _, n := range sortedCopy(d.Removed) {
			fmt.Printf("    - %s\n", n)
		}
		for _, n := range sortedCopy(d.Kept) {
			fmt.Printf("      %s (kept)\n", n)
		}
	}
	fmt.Fprintf(os.Stderr, "note: values can't be diffed (sealing is non-deterministic + offline).\n")
}

// cmdReseal handles `reseal --svc NAME --from base.env [--env-file env=path ...]`.
//
// It is a thin wrapper over the same v2 fan-out as `seal --svc`: the
// no-nonce-churn carry-over inside SealBundleV2 (reseal-if-absent,
// carry-verbatim-if-present) makes a reseal a MINIMAL-DIFF operation — a
// re-supplied unchanged key stays byte-identical, only new/changed-set keys are
// resealed.
//
// ROTATION RITUAL (lessons.md L10 — read before rotating): the authoring path
// holds neither the cluster private key nor the stored plaintext, so it CANNOT
// detect that a present key's VALUE changed (sealing is non-deterministic; a
// value compare would require decrypting). Therefore `reseal --from` alone will
// NOT re-seal an already-present key even if you edited its value in base.env —
// it carries the old ciphertext verbatim and you would ship the OLD value with
// an empty diff. To actually rotate a key you MUST first remove it from the
// prior .sealed/<svc>.app.json (so it is absent → resealed fresh), then reseal.
// Rotation is deliberate, never incidental.
func cmdReseal(args []string) {
	flags, _ := parseFlags(args)
	if flags["svc"] == "" {
		fail("reseal requires --svc NAME --from base.env [--env-file env=path ...]\n" +
			"  rotation ritual (L10): to rotate a key, first REMOVE it from\n" +
			"  .sealed/<svc>.app.json, then reseal — a present key is carried\n" +
			"  verbatim (no churn), so editing its value alone ships the OLD value.\n" +
			"  shortcut: reseal --svc NAME --rotate KEY --from base.env  (strips KEY first, then reseals it fresh)")
	}
	rc, err := client.LoadRepoConfig(".")
	if err != nil {
		fail("%v", err)
	}
	// --rotate KEY: perform the L10 remove-then-reseal ritual as one step. Strip
	// KEY from the prior bundle (so it is absent → resealed fresh from --from)
	// BEFORE the fan-out carries present keys verbatim.
	if key := flags["rotate"]; key != "" && key != "true" {
		out := filepath.Join(".sealed", flags["svc"]+".app.json")
		n, err := client.StripKeyFromBundle(out, key)
		if err != nil {
			fail("reseal --rotate %s: %v", key, err)
		}
		fmt.Fprintf(os.Stderr, "rotate: stripped %q from %d env section(s); it will be resealed fresh from --from\n", key, n)
	}
	cmdSealV2(args, flags, rc, true)
}

// parseSourceFile reads a plaintext source (env/json/yaml) into a KEY→val map.
// format "" → guessed from the path extension.
func parseSourceFile(path, format string) (map[string]string, error) {
	if format == "" {
		format = client.FormatFromPath(path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return client.ParseSource(data, format)
}

// collectEnvFileFlags scans raw args for EVERY `--env-file <value>` occurrence
// (both `--env-file x` and `--env-file=x` forms), returning each value. This
// exists because parseFlags keeps only the LAST value for a repeated flag, but
// --env-file is intentionally multi-valued (one per divergent env).
func collectEnvFileFlags(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--env-file":
			if i+1 < len(args) {
				out = append(out, args[i+1])
				i++
			}
		case strings.HasPrefix(a, "--env-file="):
			out = append(out, strings.TrimPrefix(a, "--env-file="))
		}
	}
	return out
}

// collectEnvFlags scans raw args for EVERY `--env <value>` occurrence (both
// `--env x` and `--env=x`), returning each value. Like --env-file it is
// intentionally multi-valued (`--env prod --env preprod`), so it can't rely on
// parseFlags (last-wins). It deliberately does NOT match `--env-file`
// (`--env-file` has the `--env` prefix): the space form requires the exact token
// `--env`, and the `=` form requires `--env=` (not `--env-file=`).
func collectEnvFlags(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--env":
			if i+1 < len(args) {
				out = append(out, args[i+1])
				i++
			}
		case strings.HasPrefix(a, "--env="):
			out = append(out, strings.TrimPrefix(a, "--env="))
		}
	}
	return out
}

// sortedKeysOf returns the sorted keys of a string-keyed map.
func sortedKeysOf[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func sortedCopy(s []string) []string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return c
}

func cmdUnseal(args []string) {
	flags, rest := parseFlags(args)

	// v2 selector mode: `unseal --svc NAME --env ENV --name KEY` (or --all-envs)
	// selects the per-env ciphertext from .sealed/<svc>.app.json and broker-gates
	// each entry exactly as the flat path does. Selected by --svc; when --svc is
	// absent the existing flat unseal path below is entirely unchanged.
	if flags["svc"] != "" {
		cmdUnsealV2(flags, rest)
		return
	}

	all := flags["all"] == "true"
	name := flags["name"]
	bundlePath := flags["bundle"]
	if bundlePath == "" && !all && name == "" {
		fail("unseal requires --name NAME (or --all, or --bundle FILE)")
	}
	rc, err := client.LoadRepoConfig(".")
	if err != nil {
		fail("%v", err)
	}
	token, _, err := client.ResolvePAT(env("SEALD_HOST", defaultHost), "")
	if err != nil {
		fail("%v", err)
	}
	broker := env("SEALD_BROKER", defaultBroker)

	// ciphertext source: a SealedBundle file (--bundle) OR the .sealed/*.json
	// files. Build name→ciphertext + the project id to use.
	cipherFor := map[string][]byte{}
	var names []string
	projectID := rc.ProjectID
	if bundlePath != "" {
		bdl, err := client.LoadBundle(bundlePath)
		if err != nil {
			fail("%v", err)
		}
		// AUDIT v2 #4: defense-in-depth — the bundle's project_id should match the
		// repo it lives in. (The broker is authoritative via the embedded id, but
		// catching a mismatch here is a clearer error than a broker 400.) v3 dropped
		// the field → repo.yaml is authoritative (resolveUnsealProjectID).
		pid, err := resolveUnsealProjectID(bdl.ProjectID, rc.ProjectID)
		if err != nil {
			fail("%v", err)
		}
		projectID = pid
		if all || name == "" {
			names = bdl.Names()
		} else {
			names = []string{name}
		}
		for _, n := range names {
			ct := bdl.Ciphertext(n)
			if ct == nil {
				fail("secret %q not in bundle %s", n, bundlePath)
			}
			cipherFor[n] = ct
		}
	} else {
		if all {
			names, err = client.ListSealedNames(".")
			if err != nil {
				fail("%v", err)
			}
			if len(names) == 0 {
				fail("no sealed secrets found in .sealed/")
			}
		} else {
			names = []string{name}
		}
		for _, n := range names {
			sf, err := client.LoadSealedFile(".", n)
			if err != nil {
				fail("%v", err)
			}
			ct, err := base64.StdEncoding.DecodeString(sf.Ciphertext)
			if err != nil {
				fail("corrupt sealed file %s: %v", n, err)
			}
			cipherFor[n] = ct
		}
	}

	// The flat path handles v1 flat files + --bundle (numeric project_id identity);
	// v4 per-env bundles always go through the selector path (cmdUnsealV2).
	emitUnsealed(flags, rest, broker, token, client.UnsealTarget{ProjectID: projectID}, names, cipherFor, name, all || bundlePath != "")
}

// emitUnsealed is the shared broker-unseal-then-render tail used by both the flat
// unseal path (cmdUnseal) and the v2 selector path (cmdUnsealV2). Each name is
// unsealed through the broker INDEPENDENTLY (its own live GitLab-membership check
// — a per-secret failure is reported but does not leak the others), then the
// resolved plaintexts are rendered per the output flags (inject `-- cmd`, --out/
// --format, --env-file, --export, or default stdout). `singleName` is the sole
// secret name for scalar default output; `forceMulti` marks a multi-secret run
// even if only one name resolved. The broker POST and its inputs are byte-
// identical to the pre-refactor path.
func emitUnsealed(flags map[string]string, rest []string, broker, token string, target client.UnsealTarget,
	names []string, cipherFor map[string][]byte, singleName string, forceMulti bool) {

	// Prefer SSH challenge-auth: non-replayable, tokenless, agent-backed.
	// Resolve a signer from the ssh-agent or SEALD_SSH_KEY; if none, fall back to
	// the PAT path (migration). --auth=pat forces PAT; --auth=ssh requires a signer.
	var signer *client.SSHSigner
	authMode := flags["auth"]
	if authMode != "pat" {
		s, err := client.LoadSSHSigner(env("SEALD_SSH_KEY", ""), "")
		if err == nil {
			signer = s
		} else if authMode == "ssh" {
			fail("--auth=ssh: no usable SSH signer (start ssh-agent or set SEALD_SSH_KEY): %v", err)
		}
	}

	secrets := make(map[string]string, len(names))
	var failed int
	for _, n := range names {
		var (
			pt []byte
			e  error
		)
		if signer != nil {
			pt, e = client.UnsealSSH(broker, signer, target, n, cipherFor[n])
		} else {
			pt, e = client.Unseal(broker, token, target, n, cipherFor[n])
		}
		if e != nil {
			fmt.Fprintf(os.Stderr, "sealdctl: %s: %v\n", n, e)
			failed++
			continue
		}
		secrets[n] = string(pt)
	}
	if len(secrets) == 0 {
		os.Exit(1)
	}

	multi := forceMulti || len(names) > 1
	format := flags["format"] // env|json|yaml for multi-secret output

	switch {
	case len(rest) > 0: // inject mode: run child with the secret(s) in env
		cmd := exec.Command(rest[0], rest[1:]...)
		cmd.Env = os.Environ()
		for n, v := range secrets {
			cmd.Env = append(cmd.Env, n+"="+v)
		}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if e := cmd.Run(); e != nil {
			os.Exit(1)
		}
	case flags["out"] != "" || format != "":
		f := format
		if f == "" {
			f = client.FormatFromPath(flags["out"])
		}
		rendered, err := client.RenderSecrets(secrets, f)
		if err != nil {
			fail("%v", err)
		}
		if out := flags["out"]; out != "" {
			if err := os.WriteFile(out, rendered, 0600); err != nil {
				fail("write --out: %v", err)
			}
			fmt.Fprintf(os.Stderr, "wrote %d secret(s) to %s (%s, chmod 600)\n", len(secrets), out, f)
		} else {
			os.Stdout.Write(rendered)
		}
	case flags["env-file"] != "":
		writeEnvFile(flags["env-file"], names, secrets)
		fmt.Fprintf(os.Stderr, "wrote %d secret(s) to %s\n", len(secrets), flags["env-file"])
	case flags["export"] == "true":
		for _, n := range names {
			if v, ok := secrets[n]; ok {
				fmt.Printf("export %s=%s\n", n, shellQuote(v))
			}
		}
	default:
		if multi {
			for _, n := range names {
				if v, ok := secrets[n]; ok {
					fmt.Printf("%s=%s\n", n, v)
				}
			}
		} else {
			fmt.Print(secrets[singleName])
		}
	}
	if failed > 0 {
		os.Exit(1)
	}
}

// resolveUnsealProjectID reconciles a bundle's own project_id with the repo's
// (.seald/repo.yaml). v2 carries project_id in-file and MUST match (defense-in-
// depth — the broker is authoritative via the AEAD-embedded id, but a clear local
// error beats a broker 400). v3 dropped the field (== 0), so repo.yaml
// is authoritative — exactly as the materializer resolves it. A non-zero mismatch
// is always fatal (wrong repo / tampered); a zero repo id is unusable.
func resolveUnsealProjectID(bundleID, repoID int64) (int64, error) {
	if repoID <= 0 {
		return 0, fmt.Errorf(".seald/repo.yaml has no project_id")
	}
	if bundleID != 0 && bundleID != repoID {
		return 0, fmt.Errorf("bundle project_id %d != repo project_id %d (from .seald/repo.yaml)", bundleID, repoID)
	}
	return repoID, nil
}

// checkUnsealBundleVersion gates the SELECTOR unseal path (--svc/--env): it works
// on per-env bundles (v2/v3/v4). A v1 flat bundle has no env sections — the flat
// `unseal --name` path handles those.
func checkUnsealBundleVersion(version string) error {
	if !client.IsPerEnvVersion(version) {
		return fmt.Errorf("bundle is %q, not a per-env bundle (v2/v3/v4) — use flat `unseal --name` for a v1 bundle", version)
	}
	return nil
}

// unsealTargetFor builds the broker unseal target for a bundle: v4 identifies the
// project by its pubkey (repo recipient), v1-v3 by the numeric project_id. This is
// the single place the read path decides which discriminator to send.
func unsealTargetFor(version string, projectID int64, recipient string) client.UnsealTarget {
	if version == client.BundleVersionV4 {
		return client.UnsealTarget{Recipient: recipient}
	}
	return client.UnsealTarget{ProjectID: projectID}
}

// cmdUnsealV2 is the v2 selector unseal path: `unseal --svc NAME --env ENV
// [--name KEY] [--all-envs]`. It loads .sealed/<svc>.app.json, selects the
// per-env ciphertext(s) via SelectCiphertext, and hands them to the shared
// emitUnsealed tail (so each entry is INDIVIDUALLY broker-gated — the human path
// and broker POST are unchanged). --all-envs iterates every env section, keying
// each secret ENV/KEY so a --all-envs dump does not collide same-named keys
// across envs; a single --env resolves the section's KEY (or all keys if --name
// is omitted).
func cmdUnsealV2(flags map[string]string, rest []string) {
	svc := flags["svc"]
	rc, err := client.LoadRepoConfig(".")
	if err != nil {
		fail("%v", err)
	}
	path := filepath.Join(".sealed", svc+".app.json")
	bdl, err := client.LoadBundle(path)
	if err != nil {
		fail("%v", err)
	}
	if err := checkUnsealBundleVersion(bdl.Version); err != nil {
		fail("bundle %s: %v", path, err)
	}
	// v4 identifies the project by its recipient (pubkey) — no numeric project_id
	// needed (a v4 repo.yaml carries none). v1-v3 reconcile the numeric id.
	var projectID int64
	if bdl.Version != client.BundleVersionV4 {
		if projectID, err = resolveUnsealProjectID(bdl.ProjectID, rc.ProjectID); err != nil {
			fail("%v", err)
		}
	}
	if bdl.Version == client.BundleVersionV4 && rc.Recipient == "" {
		fail("v4 bundle %s needs a recipient in .seald/repo.yaml", path)
	}

	allEnvs := flags["all-envs"] == "true"
	envSel := flags["env"]
	keySel := flags["name"]
	if !allEnvs && envSel == "" {
		fail("unseal --svc requires --env ENV (or --all-envs)")
	}

	// Build the (display-name → ciphertext) selection. The broker's `name` field
	// is advisory (the envelope's embedded project_id + ciphertext are
	// authoritative — see crypto.go / UnsealVerified), so an --all-envs run can
	// safely disambiguate same-named keys across envs as "env/KEY" without
	// affecting the live check.
	cipherFor := map[string][]byte{}
	var names []string

	addEntry := func(env, key string, multiEnv bool) {
		ct := bdl.SelectCiphertext(env, key)
		if ct == nil {
			fail("secret %q not in env %q of bundle %s", key, env, path)
		}
		disp := key
		if multiEnv {
			disp = env + "/" + key
		}
		cipherFor[disp] = ct
		names = append(names, disp)
	}

	switch {
	case allEnvs:
		for _, env := range sortedKeysOf(bdl.Envs) {
			for _, key := range sortedKeysOf(bdl.Envs[env].Entries) {
				if keySel != "" && key != keySel {
					continue
				}
				addEntry(env, key, true)
			}
		}
		if len(names) == 0 {
			fail("no matching entries across env sections of %s", path)
		}
	default: // single --env
		sec, ok := bdl.Envs[envSel]
		if !ok {
			fail("env %q not present in bundle %s", envSel, path)
		}
		if keySel != "" {
			addEntry(envSel, keySel, false)
		} else {
			for _, key := range sortedKeysOf(sec.Entries) {
				addEntry(envSel, key, false)
			}
			if len(names) == 0 {
				fail("env %q section of %s has no entries", envSel, path)
			}
		}
	}

	token, _, err := client.ResolvePAT(env("SEALD_HOST", defaultHost), "")
	if err != nil {
		fail("%v", err)
	}
	broker := env("SEALD_BROKER", defaultBroker)

	single := ""
	if len(names) == 1 {
		single = names[0]
	}
	target := unsealTargetFor(bdl.Version, projectID, rc.Recipient)
	emitUnsealed(flags, rest, broker, token, target, names, cipherFor, single, allEnvs || len(names) > 1)
}

func writeEnvFile(path string, order []string, secrets map[string]string) {
	var b strings.Builder
	for _, n := range order {
		if v, ok := secrets[n]; ok {
			fmt.Fprintf(&b, "%s=%s\n", n, v)
		}
	}
	// 0600 — the dotenv file holds plaintext secrets.
	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		fail("write env-file: %v", err)
	}
}

func cmdDoctor() {
	host := env("SEALD_HOST", defaultHost)
	token, src, err := client.ResolvePAT(host, "")
	if err != nil {
		fail("PAT: %v", err)
	}
	fmt.Printf("✓ GitLab PAT resolved (source: %s, %d chars)\n", src, len(token))
	if rc, err := client.LoadRepoConfig("."); err == nil {
		fmt.Printf("✓ repo config: project_id=%d recipient=%s\n", rc.ProjectID, rc.Recipient)
	} else {
		fmt.Printf("• no .seald/repo.yaml here (run from a sealed repo): %v\n", err)
	}
	fmt.Printf("• broker: %s\n", env("SEALD_BROKER", defaultBroker))
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
