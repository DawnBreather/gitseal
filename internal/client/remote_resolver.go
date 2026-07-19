package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// RemoteSignerResolver implements SignerResolver against the broker's
// /v1/signer/resolve endpoint: it resolves a signer fingerprint to its registered
// public key + LIVE project level. Used by `verify --authz` (CI) to enforce
// per-env-section signatures without holding the user registry. Fail-closed: any
// transport/parse error → the section is treated as unresolvable (deny).
type RemoteSignerResolver struct {
	BrokerURL string
	ProjectID int64
	// cache within one verify run (a section's signer is looked up once).
	cache map[string]remoteSigner
}

type remoteSigner struct {
	registered bool
	pub        ssh.PublicKey
	level      int
}

type signerResolveResponse struct {
	Registered bool   `json:"registered"`
	PubKey     string `json:"pubkey"`
	UserID     int64  `json:"user_id"`
	LiveLevel  int    `json:"live_level"`
}

func (r *RemoteSignerResolver) fetch(fp string) (remoteSigner, error) {
	if r.cache == nil {
		r.cache = map[string]remoteSigner{}
	}
	if s, ok := r.cache[fp]; ok {
		return s, nil
	}
	u := strings.TrimRight(r.BrokerURL, "/") + "/v1/signer/resolve?fingerprint=" +
		url.QueryEscape(fp) + "&project_id=" + strconv.FormatInt(r.ProjectID, 10)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Get(u)
	if err != nil {
		return remoteSigner{}, fmt.Errorf("signer resolve unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return remoteSigner{}, fmt.Errorf("signer resolve returned %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out signerResolveResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return remoteSigner{}, fmt.Errorf("signer resolve parse: %w", err)
	}
	s := remoteSigner{registered: out.Registered, level: out.LiveLevel}
	if out.Registered && out.PubKey != "" {
		pub, err := ParseAuthorizedKey(out.PubKey)
		if err != nil {
			return remoteSigner{}, fmt.Errorf("signer resolve bad pubkey: %w", err)
		}
		s.pub = pub
	}
	r.cache[fp] = s
	return s, nil
}

// PubKeyFor implements SignerResolver (ok=false if unregistered or on error).
func (r *RemoteSignerResolver) PubKeyFor(fingerprint string) (ssh.PublicKey, bool) {
	s, err := r.fetch(fingerprint)
	if err != nil || !s.registered || s.pub == nil {
		return nil, false
	}
	return s.pub, true
}

// LiveLevelFor implements SignerResolver (error → caller fails closed).
func (r *RemoteSignerResolver) LiveLevelFor(fingerprint string) (int, error) {
	s, err := r.fetch(fingerprint)
	if err != nil {
		return 0, err
	}
	return s.level, nil
}
