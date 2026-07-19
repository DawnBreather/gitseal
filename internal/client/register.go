package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RecipientRegistration is the payload the gitseal-controller sends to register a
// freshly-minted per-(project,env) materializer recipient with the broker.
type RecipientRegistration struct {
	ProjectRecipient string `json:"project_recipient"`
	Env              string `json:"env"`
	Recipient        string `json:"recipient"`
	Cluster          string `json:"cluster,omitempty"`
	Namespace        string `json:"namespace,omitempty"`
	MinLevel         int    `json:"min_level,omitempty"`
}

// RegisterRecipient POSTs the registration to the broker's /v1/recipient/register,
// authenticated with the shared registration token. Only the PUBLIC recipient
// crosses the wire — never a private key (invariant). A non-200 is an error
// so the controller retries + surfaces it (fail-closed: an unregistered recipient
// means seal won't target this env, never a silent wrong-key).
func RegisterRecipient(brokerURL, token string, reg RecipientRegistration) error {
	if reg.ProjectRecipient == "" || reg.Env == "" || reg.Recipient == "" {
		return fmt.Errorf("register: project_recipient, env, recipient are required")
	}
	body, _ := json.Marshal(reg)
	req, err := http.NewRequest("POST", strings.TrimRight(brokerURL, "/")+"/v1/recipient/register", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Seald-Register-Token", token)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("register recipient: broker unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("register recipient: broker returned %d: %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	return nil
}
