package broker

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dawnbreather/gitseal/internal/client"
	"github.com/dawnbreather/gitseal/internal/crypto"
)

// TestSSHUnsealE2E drives the FULL SSH challenge-auth unseal against a live
// in-process broker + stub GitLab: challenge → SSH-sign → unseal → decrypt. It
// proves (a) an SSH-authed, registered, sufficiently-privileged user gets the
// plaintext, and (b) the live-level gate still bites (a registered user BELOW the
// required level is denied — instant revocation works for SSH auth too).
func TestSSHUnsealE2E(t *testing.T) {
	const pid int64 = 412
	const svcToken = "broker-service-token"

	// an in-process SSH keypair = the "developer"
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	fp := ssh.FingerprintSHA256(sshPub)
	inSigner, _ := ssh.NewSignerFromKey(priv)
	signer := client.NewSSHSignerFrom(inSigner)

	// stub GitLab: the SERVICE token is what the SSH path uses for members/all +
	// the leg-C /users/:id account-state check.
	stub := newStub()
	stub.level[svcToken] = map[int64]int{pid: 40} // dev is Maintainer on the project
	stub.usersByIDSt[7] = "active"                // dev account is a live human
	srv := stub.serverWithLevels(t)

	// broker: repo key + registry (fp→uid 7, fp→pubkey) + challenge store + svc token
	b, kp := testBroker(t, srv.URL, pid)
	b.ServiceToken = svcToken
	b.Challenges = NewChallengeStore(time.Minute)
	b.Registry = &Registry{
		Users:    map[string]int64{fp: 7},
		UserKeys: map[string]string{fp: string(ssh.MarshalAuthorizedKey(sshPub))},
	}

	// seal a secret to the repo key (as the CLI would, offline)
	ct, err := crypto.SealWithLevel([]byte("top-secret"), kp.Recipient, pid, "API_KEY", 40)
	if err != nil {
		t.Fatal(err)
	}

	// stand the broker up as an HTTP server and drive the CLIENT SSH unseal against it
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/challenge", b.HandleChallenge)
	mux.HandleFunc("/v1/unseal", b.HandleUnseal)
	hsrv := httptest.NewServer(mux)
	defer hsrv.Close()

	pt, err := client.UnsealSSH(hsrv.URL, signer, client.UnsealTarget{ProjectID: pid}, "API_KEY", ct)
	if err != nil {
		t.Fatalf("SSH unseal (Maintainer) must succeed: %v", err)
	}
	if string(pt) != "top-secret" {
		t.Fatalf("plaintext = %q, want top-secret", pt)
	}

	// now drop the dev BELOW the secret's required level (40) → live gate denies,
	// even though SSH auth + signature are perfectly valid.
	stub.level[svcToken][pid] = 30
	if _, err := client.UnsealSSH(hsrv.URL, signer, client.UnsealTarget{ProjectID: pid}, "API_KEY", ct); err == nil {
		t.Fatal("SSH unseal must be DENIED when the signer's live level < the secret's required level")
	}

	// review BLOCKER regression test: restore level, but BLOCK the account
	// (GitLab keeps the membership row → leg D still passes). The leg-C account-state
	// check must DENY — a blocked user holding their SSH key cannot unseal.
	stub.level[svcToken][pid] = 40
	stub.usersByIDSt[7] = "blocked"
	if _, err := client.UnsealSSH(hsrv.URL, signer, client.UnsealTarget{ProjectID: pid}, "API_KEY", ct); err == nil {
		t.Fatal("SSH unseal must be DENIED for a BLOCKED user even with valid sig + retained membership")
	}
	// reactivate → allowed again (proves the gate is the state check, not a fluke)
	stub.usersByIDSt[7] = "active"
	if _, err := client.UnsealSSH(hsrv.URL, signer, client.UnsealTarget{ProjectID: pid}, "API_KEY", ct); err != nil {
		t.Fatalf("reactivated user must be allowed again: %v", err)
	}
}
