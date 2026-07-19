package broker

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dawnbreather/gitseal/internal/crypto"
)

// stubGitLab is a configurable fake GitLab API for the broker's three calls:
//
//	GET /api/v4/personal_access_tokens/self   (token liveness)
//	GET /api/v4/user                           (identity)
//	GET /api/v4/projects/{id}                  (?min_access_level=30 authz)
type stubGitLab struct {
	// keyed by token string
	tokenActive map[string]bool   // self: active && !revoked && !expired && scope ok
	userState   map[string]string // /user state: "active"
	userBot     map[string]bool   // /user bot flag
	// member[token][projectID] = has >= Developer right now
	member map[string]map[int64]bool
	// level[token][projectID] = caller's ACTUAL access level (for v2 level tests)
	level map[string]map[int64]int
	// force a transport-level failure mode for a path (status code to return raw)
	forceStatus map[string]int
	// GET /users/:id (by numeric id) → state + bot, for the SSH-path leg-C check.
	usersByIDSt  map[int64]string // uid → state ("active", "blocked", …); "" → 404
	usersByIDBot map[int64]bool
}

func newStub() *stubGitLab {
	return &stubGitLab{
		tokenActive:  map[string]bool{},
		userState:    map[string]string{},
		userBot:      map[string]bool{},
		member:       map[string]map[int64]bool{},
		level:        map[string]map[int64]int{},
		forceStatus:  map[string]int{},
		usersByIDSt:  map[int64]string{},
		usersByIDBot: map[int64]bool{},
	}
}

// serverWithLevels models GitLab's /projects/:id?min_access_level=N precisely:
// 200 iff the caller's ACTUAL level on the project >= the requested N, else 404.
// Used by the v2 per-level tests.
func (s *stubGitLab) serverWithLevels(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/personal_access_tokens/self", func(w http.ResponseWriter, r *http.Request) {
		if !s.tokenActive[r.Header.Get("PRIVATE-TOKEN")] {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"active": true, "revoked": false, "scopes": []string{"read_api"}})
	})
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("PRIVATE-TOKEN")
		st, ok := s.userState[tok]
		if !ok {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": 7, "username": "dev", "state": st, "bot": s.userBot[tok]})
	})
	// GET /users/{id} → state + bot (SSH path leg-C account-state check). "" → 404.
	mux.HandleFunc("/api/v4/users/", func(w http.ResponseWriter, r *http.Request) {
		var uid int64
		fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/api/v4/users/"), "%d", &uid)
		st, ok := s.usersByIDSt[uid]
		if !ok || st == "" {
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": uid, "state": st, "bot": s.usersByIDBot[uid]})
	})
	// members/all/{uid} → the caller's effective numeric access level.
	mux.HandleFunc("/api/v4/projects/", func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("PRIVATE-TOKEN")
		var pid int64
		fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/api/v4/projects/"), "%d", &pid)
		actual := 0
		if s.level[tok] != nil {
			actual = s.level[tok][pid]
		}
		if actual == 0 {
			w.WriteHeader(404) // not a member
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": 7, "access_level": actual})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func (s *stubGitLab) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/personal_access_tokens/self", func(w http.ResponseWriter, r *http.Request) {
		if code := s.forceStatus["self"]; code != 0 {
			w.WriteHeader(code)
			return
		}
		tok := r.Header.Get("PRIVATE-TOKEN")
		if !s.tokenActive[tok] {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"active": true, "revoked": false, "scopes": []string{"read_api"},
		})
	})
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		if code := s.forceStatus["user"]; code != 0 {
			w.WriteHeader(code)
			return
		}
		tok := r.Header.Get("PRIVATE-TOKEN")
		st, ok := s.userState[tok]
		if !ok {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"id": 7, "username": "dev", "state": st, "bot": s.userBot[tok],
		})
	})
	// GET /api/v4/projects/{id}/members/all/{uid} → effective access_level.
	// The broker resolves the caller's numeric level here (the min_access_level
	// query form is unreliable on 15.6.2-ee). `member[tok][pid]=true` models a
	// Developer (level 30) for the existing R2/R3/R4 tests.
	mux.HandleFunc("/api/v4/projects/", func(w http.ResponseWriter, r *http.Request) {
		if code := s.forceStatus["projects"]; code != 0 {
			w.WriteHeader(code)
			return
		}
		tok := r.Header.Get("PRIVATE-TOKEN")
		var pid int64
		fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/api/v4/projects/"), "%d", &pid)
		if s.member[tok] != nil && s.member[tok][pid] {
			json.NewEncoder(w).Encode(map[string]any{"id": 7, "access_level": 30})
			return
		}
		w.WriteHeader(404) // not a member
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// testBroker wires a Broker against the stub with one repo key for projectID.
func testBroker(t *testing.T, gitlabURL string, projectID int64) (*Broker, *crypto.RepoKey) {
	t.Helper()
	kp, err := crypto.GenerateRepoKey()
	if err != nil {
		t.Fatal(err)
	}
	ks := &KeyStore{
		Identities: map[int64]string{projectID: kp.Identity},
	}
	b := &Broker{
		GitLabBaseURL:   gitlabURL,
		Keys:            ks,
		RequireCFAccess: false, // deferred for v1
	}
	return b, kp
}

func unsealReq(t *testing.T, b *Broker, token string, projectID int64, ct []byte) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"project_id": projectID,
		"ciphertext": base64.StdEncoding.EncodeToString(ct),
		"name":       "DATABASE_URL",
	})
	r := httptest.NewRequest("POST", "/v1/unseal", strings.NewReader(string(body)))
	if token != "" {
		r.Header.Set("X-GitLab-Token", token)
	}
	w := httptest.NewRecorder()
	b.HandleUnseal(w, r)
	return w
}

// --- happy path ---------------------------------------------------------------

func TestUnsealHappyPath(t *testing.T) {
	s := newStub()
	srv := s.server(t)
	b, kp := testBroker(t, srv.URL, 412)
	ct, _ := crypto.Seal([]byte("the-secret"), kp.Recipient, 412, "DATABASE_URL")

	tok := "glpat-good"
	s.tokenActive[tok] = true
	s.userState[tok] = "active"
	s.userBot[tok] = false
	s.member[tok] = map[int64]bool{412: true}

	w := unsealReq(t, b, tok, 412, ct)
	if w.Code != 200 {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		PlaintextB64 string `json:"plaintext_b64"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	pt, _ := base64.StdEncoding.DecodeString(resp.PlaintextB64)
	if string(pt) != "the-secret" {
		t.Fatalf("want the-secret, got %q", pt)
	}
}

// --- R2: below Developer (404 from projects) is denied ------------------------

func TestUnsealNonMemberDenied(t *testing.T) {
	s := newStub()
	srv := s.server(t)
	b, kp := testBroker(t, srv.URL, 412)
	ct, _ := crypto.Seal([]byte("x"), kp.Recipient, 412, "DATABASE_URL")

	tok := "glpat-reporter"
	s.tokenActive[tok] = true
	s.userState[tok] = "active"
	s.member[tok] = map[int64]bool{} // not >= Developer on 412 -> 404
	w := unsealReq(t, b, tok, 412, ct)
	if w.Code != 403 {
		t.Fatalf("want 403 for non-Developer, got %d", w.Code)
	}
}

// --- R3: LIVE revocation — membership flips between two unseals (NO CACHE) ----

func TestUnsealRevocationIsLiveNoCache(t *testing.T) {
	s := newStub()
	srv := s.server(t)
	b, kp := testBroker(t, srv.URL, 412)
	ct, _ := crypto.Seal([]byte("x"), kp.Recipient, 412, "DATABASE_URL")

	tok := "glpat-dev"
	s.tokenActive[tok] = true
	s.userState[tok] = "active"
	s.member[tok] = map[int64]bool{412: true}

	if w := unsealReq(t, b, tok, 412, ct); w.Code != 200 {
		t.Fatalf("first unseal should succeed, got %d", w.Code)
	}
	// User removed from project in GitLab — no broker restart, no cache bust.
	s.member[tok][412] = false
	if w := unsealReq(t, b, tok, 412, ct); w.Code != 403 {
		t.Fatalf("after removal the very next unseal MUST be 403, got %d", w.Code)
	}
}

// --- token liveness: revoked/expired PAT dies at step B -----------------------

func TestUnsealRevokedTokenDenied(t *testing.T) {
	s := newStub()
	srv := s.server(t)
	b, kp := testBroker(t, srv.URL, 412)
	ct, _ := crypto.Seal([]byte("x"), kp.Recipient, 412, "DATABASE_URL")

	tok := "glpat-revoked"
	s.tokenActive[tok] = false // /self -> 401
	w := unsealReq(t, b, tok, 412, ct)
	if w.Code != 401 {
		t.Fatalf("want 401 for revoked token, got %d", w.Code)
	}
}

// --- identity: blocked/deactivated user denied --------------------------------

func TestUnsealBlockedUserDenied(t *testing.T) {
	s := newStub()
	srv := s.server(t)
	b, kp := testBroker(t, srv.URL, 412)
	ct, _ := crypto.Seal([]byte("x"), kp.Recipient, 412, "DATABASE_URL")

	tok := "glpat-blocked"
	s.tokenActive[tok] = true
	s.userState[tok] = "blocked" // not active
	s.member[tok] = map[int64]bool{412: true}
	w := unsealReq(t, b, tok, 412, ct)
	if w.Code != 401 {
		t.Fatalf("want 401 for blocked user, got %d", w.Code)
	}
}

// --- non-human (bot/project/group) token owner rejected -----------------------

func TestUnsealBotTokenRejected(t *testing.T) {
	s := newStub()
	srv := s.server(t)
	b, kp := testBroker(t, srv.URL, 412)
	ct, _ := crypto.Seal([]byte("x"), kp.Recipient, 412, "DATABASE_URL")

	tok := "glpat-bot"
	s.tokenActive[tok] = true
	s.userState[tok] = "active"
	s.userBot[tok] = true // project/group/impersonation token owner
	s.member[tok] = map[int64]bool{412: true}
	w := unsealReq(t, b, tok, 412, ct)
	if w.Code != 401 {
		t.Fatalf("want 401 for bot token, got %d", w.Code)
	}
}

// --- missing token -> 400 -----------------------------------------------------

func TestUnsealMissingTokenBadRequest(t *testing.T) {
	s := newStub()
	srv := s.server(t)
	b, kp := testBroker(t, srv.URL, 412)
	ct, _ := crypto.Seal([]byte("x"), kp.Recipient, 412, "DATABASE_URL")
	w := unsealReq(t, b, "", 412, ct)
	if w.Code != 400 {
		t.Fatalf("want 400 for missing token, got %d", w.Code)
	}
}

// --- R4: a token good for repo A cannot unseal repo B -------------------------

func TestUnsealCrossRepoDenied(t *testing.T) {
	s := newStub()
	srv := s.server(t)
	// broker knows key for project 100 only.
	b, kp := testBroker(t, srv.URL, 100)
	ctA, _ := crypto.Seal([]byte("secret-A"), kp.Recipient, 100, "X")

	tok := "glpat-devA"
	s.tokenActive[tok] = true
	s.userState[tok] = "active"
	s.member[tok] = map[int64]bool{100: true, 200: false} // Developer on 100, not 200

	// Attempt to unseal repo 100's blob but claim project_id 200 (which the user
	// cannot access) — must be denied at authz (404->403), never reaching decrypt.
	w := unsealReq(t, b, tok, 200, ctA)
	if w.Code != 403 {
		t.Fatalf("cross-repo: want 403, got %d", w.Code)
	}
}

// --- GitLab upstream failure (5xx) -> fail closed -----------------------------

func TestUnsealGitLabFailureFailsClosed(t *testing.T) {
	s := newStub()
	s.forceStatus["self"] = 503
	srv := s.server(t)
	b, kp := testBroker(t, srv.URL, 412)
	ct, _ := crypto.Seal([]byte("x"), kp.Recipient, 412, "DATABASE_URL")

	tok := "glpat-x"
	w := unsealReq(t, b, tok, 412, ct)
	if w.Code == 200 {
		t.Fatalf("GitLab 503 must NOT yield 200 (fail closed), got %d", w.Code)
	}
}

// --- unknown project (no key) -> deny, never decrypt --------------------------

func TestUnsealUnknownProjectDenied(t *testing.T) {
	s := newStub()
	srv := s.server(t)
	b, kp := testBroker(t, srv.URL, 412)
	ct, _ := crypto.Seal([]byte("x"), kp.Recipient, 412, "DATABASE_URL")

	tok := "glpat-dev"
	s.tokenActive[tok] = true
	s.userState[tok] = "active"
	s.member[tok] = map[int64]bool{999: true} // member of 999, which has no key
	w := unsealReq(t, b, tok, 999, ct)
	if w.Code == 200 {
		t.Fatalf("unknown project must not yield 200, got %d", w.Code)
	}
}
