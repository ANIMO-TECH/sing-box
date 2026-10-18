package authenticator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"time"
)

// HTTP delegates digest validation to the internal Java proxy-token endpoint.
// Results are never cached so replacing a token revokes new connections immediately.
type HTTP struct {
	endpoint     string
	serviceToken string
	client       *http.Client
}

var digestPattern = regexp.MustCompile(`^[a-f0-9]{56}$`)

func NewHTTP(endpoint, serviceToken string, timeout time.Duration) (*HTTP, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid authentication endpoint")
	}
	if serviceToken == "" {
		return nil, errors.New("authentication service token required")
	}
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	if timeout < 0 || timeout > 30*time.Second {
		return nil, errors.New("authentication timeout must be between zero and 30 seconds")
	}
	transport := &http.Transport{
		DialContext:  (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns: 16, MaxIdleConnsPerHost: 16, IdleConnTimeout: 60 * time.Second,
		TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout,
	}
	return &HTTP{endpoint, serviceToken, &http.Client{Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (h *HTTP) Close() { h.client.CloseIdleConnections() }

func (h *HTTP) Authenticate(ctx context.Context, digest string) (string, error) {
	if !digestPattern.MatchString(digest) {
		return "", errors.New("invalid authentication credential")
	}
	body, _ := json.Marshal(struct {
		Digest string `json:"digest"`
	}{digest})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint, bytes.NewReader(body))
	if err != nil {
		return "", errors.New("authentication request unavailable")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Gateway-Service-Token", h.serviceToken)
	response, err := h.client.Do(request)
	if err != nil {
		return "", errors.New("authentication service unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("authentication service rejected request")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil || len(data) > 8192 {
		return "", errors.New("invalid authentication response")
	}
	var result struct {
		Code   *int `json:"code"`
		Result struct {
			Valid bool   `json:"valid"`
			Email string `json:"email"`
		} `json:"result"`
	}
	if json.Unmarshal(data, &result) != nil || result.Code == nil || *result.Code != 0 || !result.Result.Valid {
		return "", errors.New("authentication denied")
	}
	email := result.Result.Email
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || address.Name != "" {
		return "", errors.New("invalid authentication identity")
	}
	return email, nil
}
