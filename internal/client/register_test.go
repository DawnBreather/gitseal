package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// RegisterRecipient POSTs a freshly-minted materializer recipient to the broker's
// /v1/recipient/register, authenticated with the shared registration
// token. Used by the gitseal-controller after it generates a per-(project,env) key.
func TestRegisterRecipient(t *testing.T) {
	var gotToken string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Seald-Register-Token")
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &gotBody)
		if gotToken != "reg-secret" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	err := RegisterRecipient(srv.URL, "reg-secret", RecipientRegistration{
		ProjectRecipient: "age1proj", Env: "prod", Recipient: "age1mat",
		Cluster: "example", Namespace: "demoapp", MinLevel: 40,
	})
	if err != nil {
		t.Fatalf("RegisterRecipient: %v", err)
	}
	if gotBody["project_recipient"] != "age1proj" || gotBody["env"] != "prod" || gotBody["recipient"] != "age1mat" {
		t.Fatalf("body wrong: %+v", gotBody)
	}
	if gotBody["namespace"] != "demoapp" || gotBody["min_level"].(float64) != 40 {
		t.Fatalf("delivery config missing: %+v", gotBody)
	}

	// a non-200 (e.g. wrong token) surfaces as an error (fail closed).
	if err := RegisterRecipient(srv.URL, "wrong", RecipientRegistration{ProjectRecipient: "a", Env: "e", Recipient: "r"}); err == nil {
		t.Fatal("bad token must return an error")
	}
}
