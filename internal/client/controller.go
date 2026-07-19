package client

// --- gitseal-controller reconcile core -------------------------------
//
// The per-cluster controller reconciles ManagedEnvironment CRs: it ensures each
// env's materializer keypair exists IN THIS CLUSTER and registers the PUBLIC
// recipient with the broker. This file is the PURE decision (no I/O) so it's
// testable; the loop that runs kubectl + RegisterRecipient wraps it (cmd/gitseal-controller).

// ManagedEnv is the reconcile input distilled from a ManagedEnvironment CR.
type ManagedEnv struct {
	ProjectRecipient string
	Env              string
	Namespace        string
	MinLevel         int
	SecretName       string // gitseal-materializer-<project>-<env>
}

// ReconcileAction is what the controller should do for one env this tick.
type ReconcileAction int

const (
	ReconcileError    ReconcileAction = iota // can't proceed (e.g. present Secret with no derivable recipient)
	ReconcileGenerate                        // no Secret → mint keypair, seed Secret, register
	ReconcileAdopt                           // Secret exists → keep it (idempotent), register its recipient
)

// ReconcilePlan is the decided action + whether/what to register.
type ReconcilePlan struct {
	Action    ReconcileAction
	Register  bool   // (re-)register the recipient with the broker (soft state → always re-assert)
	Recipient string // the recipient to register (for Adopt: the existing one; Generate fills it after minting)
}

// PlanEnvReconcile decides the action for one env. secretExists = the materializer
// Secret is already present; existingRecipient = its derived public recipient (only
// meaningful when secretExists). Idempotent: an existing key is ADOPTED (never
// regenerated — regenerating would orphan the sealed bundles until a re-seal), but
// its recipient is ALWAYS re-registered (the broker's registry is soft state it
// loses on restart). A present-but-unreadable Secret is an Error (never register a
// blank recipient — that would break seal for the env).
func PlanEnvReconcile(me ManagedEnv, secretExists bool, existingRecipient string) ReconcilePlan {
	if !secretExists {
		return ReconcilePlan{Action: ReconcileGenerate, Register: true}
	}
	if existingRecipient == "" {
		return ReconcilePlan{Action: ReconcileError, Register: false}
	}
	return ReconcilePlan{Action: ReconcileAdopt, Register: true, Recipient: existingRecipient}
}
