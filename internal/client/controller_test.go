package client

import "testing"

// planEnvReconcile is the pure decision core of the gitseal-controller:
// given a ManagedEnvironment's desired state + whether its materializer Secret
// already exists (+ its recipient if so), decide the action:
//   - Generate: no Secret yet → mint a keypair, seed the Secret, register.
//   - Adopt: Secret exists → don't regenerate (idempotent; don't churn the key);
//     register its existing recipient.
//
// Either way it ALWAYS (re-)registers the recipient — registration is soft state
// the broker loses on restart, so the controller re-asserts every reconcile.
func TestPlanEnvReconcile(t *testing.T) {
	me := ManagedEnv{ProjectRecipient: "age1proj", Env: "prod", Namespace: "demoapp", MinLevel: 40, SecretName: "gitseal-materializer-338-prod"}

	// Secret absent → Generate + register.
	a := PlanEnvReconcile(me, false, "")
	if a.Action != ReconcileGenerate || !a.Register {
		t.Fatalf("absent secret → generate+register, got %+v", a)
	}

	// Secret present → Adopt (no regenerate) + still register the existing recipient.
	a = PlanEnvReconcile(me, true, "age1existing")
	if a.Action != ReconcileAdopt || !a.Register {
		t.Fatalf("present secret → adopt+register, got %+v", a)
	}
	if a.Recipient != "age1existing" {
		t.Fatalf("adopt must register the EXISTING recipient, got %q", a.Recipient)
	}

	// Secret present but recipient un-derivable (empty) → Error (don't register a blank).
	a = PlanEnvReconcile(me, true, "")
	if a.Action != ReconcileError || a.Register {
		t.Fatalf("present-but-unreadable → error, no register, got %+v", a)
	}
}
