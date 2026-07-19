package broker

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// the broker holds a RecipientRegistry — SOFT STATE (like IdentityIndex),
// (re)populated by AUTHENTICATED controller registrations, mapping
// (projectRecipient, env) → the dynamically-minted materializer recipient. The
// snapshot overlays these onto the static projects.json recipients, so `seal`
// picks up dynamically-onboarded envs. A rogue registration would poison seal →
// the endpoint MUST require the shared registration token.
func TestRecipientRegistry_RegisterAndSnapshot(t *testing.T) {
	b := &Broker{
		RegisterToken: "reg-secret",
		Recipients:    NewRecipientRegistry(),
		Registry: &Registry{Projects: map[string]ProjectEntry{
			"age1projPUB": {ProjectID: 338, Envs: map[string]ProjectEnv{
				"prod": {Cluster: "example", Namespace: "demoapp", MinLevel: 40, Recipient: "age1STATIC"},
			}},
		}},
	}

	post := func(token, body string) int {
		r := httptest.NewRequest("POST", "/v1/recipient/register", strings.NewReader(body))
		if token != "" {
			r.Header.Set("X-Seald-Register-Token", token)
		}
		w := httptest.NewRecorder()
		b.HandleRecipientRegister(w, r)
		return w.Code
	}

	// missing/wrong token → 401, no registration
	if c := post("", `{"project_recipient":"age1projPUB","env":"prod","recipient":"age1DYN"}`); c != 401 {
		t.Fatalf("missing token want 401, got %d", c)
	}
	if c := post("nope", `{"project_recipient":"age1projPUB","env":"prod","recipient":"age1DYN"}`); c != 401 {
		t.Fatalf("bad token want 401, got %d", c)
	}

	// valid registration for a NEW env (qa) → 200
	if c := post("reg-secret", `{"project_recipient":"age1projPUB","env":"qa","recipient":"age1QADYN","cluster":"example","namespace":"demoapp-qa","min_level":40}`); c != 200 {
		t.Fatalf("valid register want 200, got %d", c)
	}
	// re-register prod with a DYNAMIC recipient → overlays the static one
	if c := post("reg-secret", `{"project_recipient":"age1projPUB","env":"prod","recipient":"age1PRODDYN","cluster":"example","namespace":"demoapp","min_level":40}`); c != 200 {
		t.Fatalf("prod re-register want 200, got %d", c)
	}

	// snapshot: prod recipient is now the DYNAMIC one (overlay), qa appears
	rr := httptest.NewRecorder()
	b.HandleRegistrySnapshot(rr, httptest.NewRequest("GET", "/v1/registry/snapshot", nil))
	var snap RegistrySnapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
		t.Fatalf("snapshot json: %v", err)
	}
	p := snap.Projects["age1projPUB"]
	if p.Envs["prod"].Recipient != "age1PRODDYN" {
		t.Fatalf("prod recipient should be the dynamic overlay, got %q", p.Envs["prod"].Recipient)
	}
	if p.Envs["qa"].Recipient != "age1QADYN" || p.Envs["qa"].Namespace != "demoapp-qa" {
		t.Fatalf("qa env not registered into snapshot: %+v", p.Envs["qa"])
	}
	// the static config for prod (namespace, min_level) is preserved under the overlay
	if p.Envs["prod"].Namespace != "demoapp" || p.Envs["prod"].MinLevel != 40 {
		t.Fatalf("prod static config lost under overlay: %+v", p.Envs["prod"])
	}
}

// A registration for an unknown project (no static entry) still registers — the
// project entry is created from the registration (a fully dynamically-onboarded
// project). project_recipient + env + recipient are required (400 if missing).
func TestRecipientRegistry_Validation(t *testing.T) {
	b := &Broker{RegisterToken: "t", Recipients: NewRecipientRegistry(), Registry: &Registry{Projects: map[string]ProjectEntry{}}}
	post := func(body string) int {
		r := httptest.NewRequest("POST", "/v1/recipient/register", strings.NewReader(body))
		r.Header.Set("X-Seald-Register-Token", "t")
		w := httptest.NewRecorder()
		b.HandleRecipientRegister(w, r)
		return w.Code
	}
	if post(`{"env":"prod","recipient":"age1x"}`) != 400 {
		t.Fatal("missing project_recipient must be 400")
	}
	if post(`{"project_recipient":"age1p","recipient":"age1x"}`) != 400 {
		t.Fatal("missing env must be 400")
	}
	if post(`{"project_recipient":"age1p","env":"prod"}`) != 400 {
		t.Fatal("missing recipient must be 400")
	}
}

// Peer fan-out: an ORIGINAL registration to one replica must be
// forwarded to peers (marked X-Seald-Forwarded so they don't re-fan), so every
// replica's snapshot converges. A FORWARDED registration must NOT fan out again
// (loop-breaker). We drive fan-out through the peerURLs seam pointed at a stub peer.
func TestRecipientRegistry_FanOut(t *testing.T) {
	// stub "peer" replica: a real broker behind an httptest server that records the
	// forwarded-header + token of each request it receives before handling it.
	var mu sync.Mutex
	var got []struct{ forwarded, token string }
	peerB := &Broker{RegisterToken: "reg-secret", Recipients: NewRecipientRegistry(), Registry: &Registry{Projects: map[string]ProjectEntry{}}}
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		got = append(got, struct{ forwarded, token string }{req.Header.Get("X-Seald-Forwarded"), req.Header.Get("X-Seald-Register-Token")})
		mu.Unlock()
		peerB.HandleRecipientRegister(w, req)
	}))
	defer peer.Close()

	origin := &Broker{
		RegisterToken: "reg-secret",
		Recipients:    NewRecipientRegistry(),
		Registry:      &Registry{Projects: map[string]ProjectEntry{}},
		peerURLs:      func() []string { return []string{peer.URL} },
	}

	// ORIGINAL registration (no X-Seald-Forwarded) → fans out to the peer.
	r := httptest.NewRequest("POST", "/v1/recipient/register",
		strings.NewReader(`{"project_recipient":"age1p","env":"prod","recipient":"age1DYN","namespace":"demoapp","min_level":40}`))
	r.Header.Set("X-Seald-Register-Token", "reg-secret")
	w := httptest.NewRecorder()
	origin.HandleRecipientRegister(w, r)
	if w.Code != 200 {
		t.Fatalf("origin register want 200, got %d", w.Code)
	}

	// fan-out is async — wait for the peer to receive it.
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("peer should have received exactly 1 forwarded registration, got %d", len(got))
	}
	if got[0].forwarded != "1" {
		t.Fatalf("forwarded registration must carry X-Seald-Forwarded=1, got %q", got[0].forwarded)
	}
	if got[0].token != "reg-secret" {
		t.Fatalf("forwarded registration must carry the register token, got %q", got[0].token)
	}
	// the peer now serves the recipient in ITS snapshot (convergence proven)
	if peerB.Recipients.forProject("age1p")["prod"].Recipient != "age1DYN" {
		t.Fatal("peer registry did not converge on the forwarded recipient")
	}
}

// A FORWARDED registration must not itself fan out (loop-breaker): with a peerURLs
// seam that would panic if called, a request bearing X-Seald-Forwarded stays local.
func TestRecipientRegistry_ForwardedDoesNotRefan(t *testing.T) {
	var fanCalls int32
	b := &Broker{
		RegisterToken: "t",
		Recipients:    NewRecipientRegistry(),
		Registry:      &Registry{Projects: map[string]ProjectEntry{}},
		peerURLs:      func() []string { atomic.AddInt32(&fanCalls, 1); return nil },
	}
	r := httptest.NewRequest("POST", "/v1/recipient/register",
		strings.NewReader(`{"project_recipient":"age1p","env":"prod","recipient":"age1x"}`))
	r.Header.Set("X-Seald-Register-Token", "t")
	r.Header.Set("X-Seald-Forwarded", "1")
	w := httptest.NewRecorder()
	b.HandleRecipientRegister(w, r)
	if w.Code != 200 {
		t.Fatalf("forwarded register want 200, got %d", w.Code)
	}
	if atomic.LoadInt32(&fanCalls) != 0 {
		t.Fatal("a forwarded registration must NOT trigger peer discovery / fan-out")
	}
	if b.Recipients.forProject("age1p")["prod"].Recipient != "age1x" {
		t.Fatal("forwarded registration must still apply locally")
	}
}

// Disabled (no RegisterToken) → endpoint 503, never an open door on a decrypting service.
func TestRecipientRegister_DisabledWithoutToken(t *testing.T) {
	b := &Broker{Recipients: NewRecipientRegistry()}
	r := httptest.NewRequest("POST", "/v1/recipient/register", strings.NewReader(`{}`))
	r.Header.Set("X-Seald-Register-Token", "anything")
	w := httptest.NewRecorder()
	b.HandleRecipientRegister(w, r)
	if w.Code == 200 {
		t.Fatal("register must be disabled (not 200) without a RegisterToken")
	}
}
