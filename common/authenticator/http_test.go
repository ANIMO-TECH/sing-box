package authenticator

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPAuthentication(t *testing.T) {
	for _, test := range []struct {
		name, body string
		status     int
		valid      bool
	}{
		{"valid", `{"code":0,"result":{"valid":true,"email":"admin@example.com"}}`, 200, true},
		{"expired", `{"code":0,"result":{"valid":false}}`, 200, false},
		{"missing code", `{"result":{"valid":true,"email":"admin@example.com"}}`, 200, false},
		{"unauthorized", `{}`, 401, false},
		{"invalid identity", `{"code":0,"result":{"valid":true,"email":"Admin <admin@example.com>"}}`, 200, false},
		{"malformed", `{`, 200, false},
		{"too large", strings.Repeat("x", 8193), 200, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.Header.Get("X-Gateway-Service-Token") != "test-service" {
					t.Error("request contract mismatch")
				}
				var payload map[string]string
				if json.NewDecoder(r.Body).Decode(&payload) != nil || payload["digest"] != strings.Repeat("a", 56) {
					t.Error("digest mismatch")
				}
				w.WriteHeader(test.status)
				io.WriteString(w, test.body)
			}))
			defer server.Close()
			client, err := NewHTTP(server.URL, "test-service", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			email, err := client.Authenticate(context.Background(), strings.Repeat("a", 56))
			if (err == nil) != test.valid {
				t.Fatalf("unexpected outcome: %v", err)
			}
			if test.valid && email != "admin@example.com" {
				t.Fatal("identity mismatch")
			}
		})
	}
}

func TestRedirectIsNeverFollowedAndMalformedCredentialNeverSent(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Redirect(w, r, "/unexpected", http.StatusFound)
	}))
	defer server.Close()
	client, _ := NewHTTP(server.URL, "test-service", time.Second)
	defer client.Close()
	if _, err := client.Authenticate(context.Background(), "bad"); err == nil || calls != 0 {
		t.Fatal("malformed credential was sent")
	}
	if _, err := client.Authenticate(context.Background(), strings.Repeat("a", 56)); err == nil || calls != 1 {
		t.Fatal("redirect followed")
	}
}

func TestAuthenticationTimeoutAndNoCachedSuccess(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			io.WriteString(w, `{"code":0,"result":{"valid":true,"email":"admin@example.com"}}`)
			return
		}
		time.Sleep(250 * time.Millisecond)
	}))
	defer server.Close()
	client, _ := NewHTTP(server.URL, "test-service", 100*time.Millisecond)
	defer client.Close()
	if _, err := client.Authenticate(context.Background(), strings.Repeat("a", 56)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Authenticate(context.Background(), strings.Repeat("a", 56)); err == nil {
		t.Fatal("unexpected cached success")
	}
}
