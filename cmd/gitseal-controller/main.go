// Command gitseal-controller is the per-cluster reconciler for ManagedEnvironment
// CRs. Dependency-light on purpose: it SHELLS to kubectl (like the
// materializer) rather than pulling controller-runtime/client-go — the CRD is real,
// but the "controller" is a poll loop of the same family as the materializer.
//
// Each tick, for every ManagedEnvironment in this cluster:
//  1. ensure the env's materializer keypair exists (Secret gitseal-materializer-
//     <project>-<env> in ns seald): GENERATE + seed if absent (private half never
//     leaves the cluster), else ADOPT the existing key;
//  2. REGISTER the PUBLIC recipient with the broker (authenticated) — soft state
//     the broker loses on restart, so re-asserted every tick;
//  3. patch .status (recipient, phase).
//
// Config (env): SEALD_BROKER (broker base URL), SEALD_REGISTER_TOKEN (shared secret),
// SEALD_CLUSTER (this cluster's name, stamped into the registration),
// SEALD_RECONCILE_INTERVAL (default 60s), SEALD_KEY_NAMESPACE (default seald).
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dawnbreather/gitseal/internal/client"
	"github.com/dawnbreather/gitseal/internal/crypto"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	broker := os.Getenv("SEALD_BROKER")
	token := os.Getenv("SEALD_REGISTER_TOKEN")
	cluster := os.Getenv("SEALD_CLUSTER")
	keyNS := env("SEALD_KEY_NAMESPACE", "seald")
	if broker == "" || token == "" {
		fmt.Fprintln(os.Stderr, "gitseal-controller: SEALD_BROKER and SEALD_REGISTER_TOKEN are required")
		os.Exit(2)
	}
	interval := 60 * time.Second
	if v := os.Getenv("SEALD_RECONCILE_INTERVAL"); v != "" {
		if d, e := time.ParseDuration(v); e == nil && d > 0 {
			interval = d
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	fmt.Printf("gitseal-controller: reconciling ManagedEnvironments every %s → broker %s (cluster %q)\n", interval, broker, cluster)
	reconcileAll(broker, token, cluster, keyNS) // prime immediately
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Println("gitseal-controller: shutting down")
			return
		case <-t.C:
			reconcileAll(broker, token, cluster, keyNS)
		}
	}
}

// managedEnvList is the minimal shape we read from `kubectl get managedenvironments`.
type managedEnvList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			Project          string `json:"project"`
			ProjectRecipient string `json:"projectRecipient"`
			Env              string `json:"env"`
			Namespace        string `json:"namespace"`
			MinLevel         int    `json:"minLevel"`
		} `json:"spec"`
	} `json:"items"`
}

func reconcileAll(broker, token, cluster, keyNS string) {
	// ManagedEnvironment is namespaced — it lives in the key namespace (seald).
	out, err := exec.Command("kubectl", "-n", keyNS, "get", "managedenvironments", "-o", "json").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "list managedenvironments: %v\n", err)
		return
	}
	var list managedEnvList
	if err := json.Unmarshal(out, &list); err != nil {
		fmt.Fprintf(os.Stderr, "parse managedenvironments: %v\n", err)
		return
	}
	for _, it := range list.Items {
		if it.Spec.Project == "" {
			fmt.Fprintf(os.Stderr, "reconcile %s: spec.project is required\n", it.Metadata.Name)
			patchStatus(keyNS, it.Metadata.Name, "", "Error", "spec.project required")
			continue
		}
		me := client.ManagedEnv{
			ProjectRecipient: it.Spec.ProjectRecipient,
			Env:              it.Spec.Env,
			Namespace:        it.Spec.Namespace,
			MinLevel:         it.Spec.MinLevel,
			SecretName:       fmt.Sprintf("gitseal-materializer-%s-%s", it.Spec.Project, it.Spec.Env),
		}
		if err := reconcileOne(it.Metadata.Name, me, broker, token, cluster, keyNS); err != nil {
			fmt.Fprintf(os.Stderr, "reconcile %s: %v\n", it.Metadata.Name, err)
			patchStatus(keyNS, it.Metadata.Name, "", "Error", err.Error())
		}
	}
}

func reconcileOne(name string, me client.ManagedEnv, broker, token, cluster, keyNS string) error {
	if me.ProjectRecipient == "" || me.Env == "" {
		return fmt.Errorf("spec missing projectRecipient/env")
	}
	// re-derive SecretName from the CR name (shortProject) — already set by caller.
	exists, existingIdent := getMaterializerIdentity(keyNS, me.SecretName)
	var existingRecip string
	if exists && existingIdent != "" {
		if r, e := client.RecipientFromIdentity(existingIdent); e == nil {
			existingRecip = r
		}
	}
	plan := client.PlanEnvReconcile(me, exists, existingRecip)

	var recipient string
	switch plan.Action {
	case client.ReconcileGenerate:
		kp, err := crypto.GenerateRepoKey()
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}
		if err := seedIdentitySecret(keyNS, me.SecretName, kp.Identity); err != nil {
			return fmt.Errorf("seed secret: %w", err)
		}
		recipient = kp.Recipient
		fmt.Printf("  %s: minted materializer key → %s (recipient %s)\n", name, me.SecretName, recipient)
	case client.ReconcileAdopt:
		recipient = plan.Recipient
		fmt.Printf("  %s: adopted existing key %s (recipient %s)\n", name, me.SecretName, recipient)
	default:
		return fmt.Errorf("secret %s present but recipient not derivable", me.SecretName)
	}

	if plan.Register {
		if err := client.RegisterRecipient(broker, token, client.RecipientRegistration{
			ProjectRecipient: me.ProjectRecipient, Env: me.Env, Recipient: recipient,
			Cluster: cluster, Namespace: me.Namespace, MinLevel: me.MinLevel,
		}); err != nil {
			return fmt.Errorf("register recipient: %w", err)
		}
	}
	patchStatus(keyNS, name, recipient, "Registered", "")
	return nil
}

// getMaterializerIdentity reads the identity Secret; returns (exists, identity).
func getMaterializerIdentity(ns, secret string) (bool, string) {
	out, err := exec.Command("kubectl", "-n", ns, "get", "secret", secret,
		"-o", "jsonpath={.data.identity}").Output()
	if err != nil {
		return false, "" // not found (or error) → treat as absent
	}
	b64 := strings.TrimSpace(string(out))
	if b64 == "" {
		return false, ""
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return true, "" // present but unreadable → Error path
	}
	return true, string(raw)
}

// seedIdentitySecret creates the materializer identity Secret (key 'identity').
func seedIdentitySecret(ns, secret, identity string) error {
	m := map[string]any{
		"apiVersion": "v1", "kind": "Secret",
		"metadata": map[string]any{"name": secret, "namespace": ns,
			"labels": map[string]string{"app.kubernetes.io/managed-by": "gitseal-controller"}},
		"data": map[string]string{"identity": base64.StdEncoding.EncodeToString([]byte(identity))},
	}
	b, _ := json.Marshal(m)
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(string(b))
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// patchStatus writes the CR .status subresource (best-effort — status is
// observability, not correctness).
func patchStatus(ns, name, recipient, phase, message string) {
	st := map[string]any{"status": map[string]any{
		"recipient": recipient, "phase": phase, "message": message,
		"lastRegistered": "",
	}}
	b, _ := json.Marshal(st)
	cmd := exec.Command("kubectl", "-n", ns, "patch", "managedenvironment", name,
		"--subresource=status", "--type=merge", "-p", string(b))
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	_ = cmd.Run()
}
