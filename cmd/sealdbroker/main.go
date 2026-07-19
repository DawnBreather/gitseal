// Command sealdbroker is the in-cluster gitseal unseal service.
//
// Config via env:
//
//	SEALD_GITLAB_URL    base URL of GitLab (e.g. https://gitlab.example.com)
//	SEALD_KEYS_DIR      directory of per-repo <pid>.key.json files (PREFERRED — a
//	                    bad key downs only its repo, not the fleet). If set, wins.
//	SEALD_BUNDLE_PATH   path to the monolithic seald-root-decrypted bundle JSON
//	                    (LEGACY — one parse error takes every repo down; kept for
//	                    the gated cutover, used only when SEALD_KEYS_DIR is unset)
//	SEALD_LISTEN        listen address (default :8080)
//	SEALD_REQUIRE_CF    "true" to require a Cloudflare Access assertion (v1: false)
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dawnbreather/gitseal/internal/broker"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	gitlabURL := os.Getenv("SEALD_GITLAB_URL")
	keysDir := os.Getenv("SEALD_KEYS_DIR")
	bundlePath := os.Getenv("SEALD_BUNDLE_PATH")
	listen := os.Getenv("SEALD_LISTEN")
	if listen == "" {
		listen = ":8080"
	}
	if gitlabURL == "" || (keysDir == "" && bundlePath == "") {
		log.Error("config", "err", "SEALD_GITLAB_URL and one of SEALD_KEYS_DIR / SEALD_BUNDLE_PATH are required")
		os.Exit(2)
	}

	// Prefer the per-repo directory keystore (a bad key downs only its own repo);
	// fall back to the legacy monolithic bundle only when the dir is unset (gated
	// cutover). A skipped key is NON-fatal in dir mode; it is surfaced by /readyz.
	var (
		ks      *broker.KeyStore
		skipped []string
		err     error
	)
	if keysDir != "" {
		ks, skipped, err = broker.LoadKeyStoreDir(keysDir)
	} else {
		ks, err = broker.LoadKeyStore(bundlePath)
	}
	if err != nil {
		log.Error("keystore", "err", err.Error())
		os.Exit(1)
	}
	b := &broker.Broker{
		GitLabBaseURL:   gitlabURL,
		Keys:            ks,
		Skipped:         skipped,
		RequireCFAccess: os.Getenv("SEALD_REQUIRE_CF") == "true",
		Logger:          log,
	}
	for _, s := range skipped {
		log.Warn("keystore: skipped key file (degraded — this repo cannot unseal)", "detail", s)
	}

	// Registry (Stage C): the broker is the authority for the project
	// config (snapshot) + user registry. Optional (SEALD_REGISTRY_DIR unset → the
	// registry endpoints are simply empty), so it can be rolled out incrementally.
	if regDir := os.Getenv("SEALD_REGISTRY_DIR"); regDir != "" {
		reg, err := broker.LoadRegistry(regDir)
		if err != nil {
			log.Error("registry", "err", err.Error())
			os.Exit(1)
		}
		b.Registry = reg
		log.Info("registry loaded", "dir", regDir, "projects", len(reg.Projects), "users", len(reg.Users))
	}

	// SSH challenge-auth (Stage D): enabled when a service token is set
	// (used for the leg-D member lookup on behalf of an SSH-authed caller). PAT auth
	// keeps working regardless (migration). The service token is a NON-admin
	// read_api token — same scope the broker already needs.
	if st := os.Getenv("SEALD_SERVICE_TOKEN"); st != "" {
		b.ServiceToken = st
		b.Challenges = broker.NewChallengeStore(2 * time.Minute)
		// build the developer identity index from GitLab (project members →
		// their profile SSH keys) instead of a hand-maintained users.json. Enabled
		// with the service token (same non-admin read_api token). The poll loop below
		// keeps it fresh; on-miss refresh + system hooks cut the latency.
		b.Identity = broker.NewIdentityIndex()
		log.Info("ssh challenge-auth enabled", "identity_index", "gitlab-backed")
	}

	// System-hook receiver: a shared secret enables the endpoint that
	// GitLab posts key/membership events to → instant index reconcile (latency
	// layer over the poll). Disabled (endpoint 503s) until the secret is set.
	if ht := os.Getenv("SEALD_SYSTEM_HOOK_TOKEN"); ht != "" {
		b.SystemHookToken = ht
		log.Info("system-hook receiver enabled")
	}

	// dynamic recipient registration. The shared token enables the endpoint
	// gitseal-controllers POST freshly-minted materializer recipients to; the snapshot
	// overlays them onto the static config. Disabled (endpoint 503s) without a token.
	b.Recipients = broker.NewRecipientRegistry()
	if rt := os.Getenv("SEALD_REGISTER_TOKEN"); rt != "" {
		b.RegisterToken = rt
		log.Info("recipient registration enabled")
		// Peer fan-out: with >1 replica the registry (per-pod soft state)
		// must be replicated on write. SEALD_PEER_DNS = a HEADLESS Service resolving
		// to all broker pod IPs; SEALD_POD_IP (downward API) excludes self. Unset →
		// single-replica / fan-out off (a controller re-register still converges).
		if pd := os.Getenv("SEALD_PEER_DNS"); pd != "" {
			b.PeerDNS = pd
			b.SelfIP = os.Getenv("SEALD_POD_IP")
			b.PeerPort = os.Getenv("SEALD_PEER_PORT")
			log.Info("recipient fan-out enabled", "peer_dns", pd, "self_ip", b.SelfIP)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/unseal", b.HandleUnseal)
	mux.HandleFunc("/v1/challenge", b.HandleChallenge)                  // SSH challenge nonce (Stage D)
	mux.HandleFunc("/v1/challenge/consume", b.HandleChallengeConsume)   // peer nonce-consume (replica fan-out)
	mux.HandleFunc("/v1/registry/snapshot", b.HandleRegistrySnapshot)   // JWKS-style public snapshot
	mux.HandleFunc("/v1/signer/resolve", b.HandleSignerResolve)         // CI write-authz signer resolution
	mux.HandleFunc("/v1/gitlab/system-hook", b.HandleSystemHook)        // GitLab system-hook receiver
	mux.HandleFunc("/v1/recipient/register", b.HandleRecipientRegister) // controller recipient registration
	mux.HandleFunc("/healthz", b.HandleHealthz)                         // liveness only
	mux.HandleFunc("/readyz", b.HandleReadyz)                           // positive readiness: >=1 key + degraded set

	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	// Hot-reload the keystore dir (poll-based; robust to projected-Secret relinks)
	// so an onboarded/rotated key is picked up WITHOUT a broker restart, with the
	// never-shrink-below-last-known-good invariant inside SwapKeys. Only in dir
	// mode (the legacy monolith has no reload path). ctx cancels on shutdown.
	reloadCtx, cancelReload := context.WithCancel(context.Background())
	defer cancelReload()
	if keysDir != "" {
		interval := 30 * time.Second
		if v := os.Getenv("SEALD_RELOAD_INTERVAL"); v != "" {
			if d, e := time.ParseDuration(v); e == nil && d > 0 {
				interval = d
			}
		}
		go b.PollReload(reloadCtx, keysDir, interval)
		log.Info("keystore hot-reload enabled", "dir", keysDir, "interval", interval.String())
	}

	// reconcile the identity index from GitLab on a poll (source of truth;
	// system hooks, if configured, are a latency layer on top). Only when enabled
	// (service token present). Primes immediately inside PollIdentityIndex.
	if b.Identity != nil {
		ivl := 5 * time.Minute
		if v := os.Getenv("SEALD_IDENTITY_INTERVAL"); v != "" {
			if d, e := time.ParseDuration(v); e == nil && d > 0 {
				ivl = d
			}
		}
		go b.PollIdentityIndex(reloadCtx, ivl)
		log.Info("identity index reconcile enabled", "interval", ivl.String())
	}

	go func() {
		log.Info("listening", "addr", listen, "projects", len(ks.Identities), "skipped", len(skipped), "require_cf", b.RequireCFAccess)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("serve", "err", err.Error())
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	cancelReload()
	// In-process drain: flip /readyz to 503 so kube-proxy removes this pod from the
	// Service endpoints, wait a grace window for that to propagate, THEN shut down
	// gracefully — the distroless-safe equivalent of a preStop sleep.
	b.BeginDrain()
	log.Info("draining", "grace", "3s")
	time.Sleep(3 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	log.Info("shutdown")
}
