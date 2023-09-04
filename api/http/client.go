// Copyright 2023 Northern.tech AS
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package http

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/northerntechhq/nt-connect/api"
	apiws "github.com/northerntechhq/nt-connect/api/ws"
	"github.com/northerntechhq/nt-connect/config"
)

type HTTPClient struct {
	PrivateKey crypto.Signer `json:"-"`

	Identity *api.Identity

	serverURL string
	client    *http.Client
	wsClient  *apiws.Client
}

var _ api.Client = &HTTPClient{}

// NewAuthClient returns a new AuthClient
func NewClient(
	cfg config.APIConfig,
	tlsConfig *tls.Config,
) (*HTTPClient, error) {
	if cfg.GetPrivateKey() == nil {
		return nil, fmt.Errorf("invalid client config: empty private key")
	} else if cfg.GetIdentity() == nil {
		return nil, fmt.Errorf("invalid client config: empty identity data")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig.Clone()

	var localAuth = HTTPClient{
		serverURL:  strings.TrimRight(cfg.ServerURL, "/"),
		PrivateKey: cfg.GetPrivateKey(),
		Identity:   cfg.GetIdentity(),
		client: &http.Client{
			Transport: transport,
		},
		wsClient: apiws.NewClient(tlsConfig),
	}
	return &localAuth, nil
}

// FetchJWTToken schedules the fetching of a new device JWT token
func (a *HTTPClient) Authenticate(ctx context.Context) (*api.Authz, error) {
	const APIURLAuth = "/api/devices/v1/authentication/auth_requests"
	bodyBytes, _ := json.Marshal(a.Identity)

	dgst := sha256.Sum256(bodyBytes)
	sig, err := a.PrivateKey.Sign(rand.Reader, dgst[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	sig64 := base64.StdEncoding.EncodeToString(sig)

	url := a.serverURL + APIURLAuth
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Men-Signature", sig64)
	rsp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	if rsp.StatusCode >= 300 {
		return nil, &api.Error{
			Code: http.StatusUnauthorized,
		}
	}
	b, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}
	return &api.Authz{
		ServerURL: a.serverURL,
		Token:     string(b),
	}, nil
}

func (a *HTTPClient) OpenSocket(ctx context.Context, authz *api.Authz) (api.Socket, error) {
	if authz.IsZero() {
		return nil, &api.Error{Code: http.StatusUnauthorized}
	}
	sock, err := a.wsClient.OpenSocket(ctx, authz)
	if err != nil {
		return nil, err
	}
	return sock, nil
}

func (a *HTTPClient) SendInventory(ctx context.Context, authz *api.Authz, inv api.Inventory) error {
	const APIURLInventory = "/api/devices/v1/inventory/attributes"
	if authz.IsZero() {
		return &api.Error{Code: http.StatusUnauthorized}
	}

	bodyBytes, _ := json.Marshal(inv)

	url := a.serverURL + APIURLInventory
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+authz.Token)
	req.Header.Set("Content-Type", "application/json")
	rsp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()
	if rsp.StatusCode >= 300 {
		return &api.Error{
			Code: rsp.StatusCode,
		}
	}
	return nil
}
