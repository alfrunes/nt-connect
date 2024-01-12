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
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/northerntechhq/nt-connect/api"
	"github.com/northerntechhq/nt-connect/config"
	"github.com/stretchr/testify/assert"
)

type requestAssertionFunc func(t *testing.T, req *http.Request) (*http.Response, error)

func (f requestAssertionFunc) RoundTripper(t *testing.T) http.RoundTripper {
	return rtFunc(func(req *http.Request) (*http.Response, error) {
		return f(t, req)
	})
}

var (
	pkey   crypto.Signer
	pubKey string
)

func init() {
	var err error
	pkey, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	public, err := x509.MarshalPKIXPublicKey(pkey.Public())
	if err != nil {
		panic(err)
	}
	pubKey = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: public,
	}))
}

func TestNewClient(t *testing.T) {
	t.Parallel()

	testDir := t.TempDir()
	b, err := x509.MarshalPKCS8PrivateKey(pkey)
	if err != nil {
		t.Errorf("failed to setup test case: %s", err)
		t.FailNow()
	}

	var (
		privateKeyPath string
		identityPath   string
	)
	fd, err := os.CreateTemp(testDir, "private-*.pem")
	if err == nil {
		_, err = fd.Write(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}))
		privateKeyPath = fd.Name()
		fd.Close()
	}
	if err != nil {
		t.Errorf("failed to setup test key: %s", err)
		t.FailNow()
	}

	fd, err = os.CreateTemp(testDir, "identity-*.pem")
	if err == nil {
		err = json.NewEncoder(fd).
			Encode(map[string]interface{}{
				`id_data`: `{"mac":"00:00:00:00:00:00"}`,
				`pubkey`:  pubKey,
			})
		identityPath = fd.Name()
		fd.Close()
	}
	if err != nil {
		t.Errorf("failed to setup test identity: %s", err)
		t.FailNow()
	}

	t.Run("ok", func(t *testing.T) {
		t.Parallel()
		validConfig := config.APIConfig{
			APIType:        config.APITypeHTTP,
			ServerURL:      "http://localhost:1234",
			PrivateKeyPath: privateKeyPath,
			IdentityPath:   identityPath,
			ExternalID:     `foo/bar`,
			TenantToken:    "tenantToken",
		}
		if assert.NoError(t, validConfig.Validate()) {
			c, err := NewClient(validConfig, nil)
			assert.NoError(t, err)
			assert.NotNil(t, c)
		}

	})
	t.Run("error/empty config", func(t *testing.T) {
		t.Parallel()
		_, err := NewClient(config.APIConfig{}, nil)
		assert.EqualError(t, err, "invalid client config: empty private key")
	})
	t.Run("error/missing private key", func(t *testing.T) {
		validConfig := config.APIConfig{
			APIType:      config.APITypeHTTP,
			ServerURL:    "http://localhost:1234",
			IdentityPath: identityPath,
			ExternalID:   `foo/bar`,
		}
		if assert.Error(t, validConfig.Validate()) {
			_, err := NewClient(validConfig, nil)
			assert.EqualError(t, err, "invalid client config: empty private key")
		}
	})
}

func newTestClient(t *testing.T, f requestAssertionFunc, opts ...func(*HTTPClient)) *HTTPClient {
	identity := api.Identity{
		Data:       `{"testing":"testing"}`,
		PublicKey:  pubKey,
		ExternalID: "testing/testing",
		TenantToken: strings.Join([]string{
			"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
			"eyJqdGkiOiIzOWE0MzYyMi0zNmIyLTQ2Y2MtYTEzMy0zMGQzM" +
				"zk0ZThmNjkiLCJzdWIiOiJ0ZXN0ZXIifQ",
			"mMXi4aTu2aPLsbmMwIf43NfMAenY8MUcdonjNpSy",
		}, "."),
	}
	ret := &HTTPClient{
		client: &http.Client{
			Transport: f.RoundTripper(t),
		},
		wsClient: dummySockClient{},

		PrivateKey: pkey,
		Identity:   &identity,
		serverURL:  "http+testing://localhost:1234",
	}
	for _, opt := range opts {
		opt(ret)
	}
	return ret
}

func TestAuthenticate(t *testing.T) {
	t.Parallel()

	var errInternal = errors.New("internal error")

	type testCase struct {
		CTX            context.Context
		StatusCode     int
		RoundTripError error

		ServerURL string
		Token     string

		crypto.Signer

		assert.ErrorAssertionFunc
	}

	for name, test := range map[string]testCase{
		"ok": {
			CTX:        context.Background(),
			StatusCode: http.StatusOK,

			Token: "token",
		},
		"error/bad signer": {
			CTX:        context.Background(),
			StatusCode: http.StatusOK,

			Signer: badSigner{},

			ErrorAssertionFunc: func(t assert.TestingT, err error, i ...interface{}) bool {
				return errors.Is(err, badSignerError)
			},
		},
		"error/roundtrip": {
			CTX:            context.Background(),
			StatusCode:     http.StatusBadRequest,
			RoundTripError: errInternal,

			Token: "token",

			ErrorAssertionFunc: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, errInternal)
			},
		},
		"error/bad status": {
			CTX:        context.Background(),
			StatusCode: http.StatusBadGateway,

			Token: "token",

			ErrorAssertionFunc: func(t assert.TestingT, err error, i ...interface{}) bool {
				var apiErr *api.Error
				return assert.ErrorAs(t, err, &apiErr) && assert.Equal(t, http.StatusBadGateway, apiErr.Code)
			},
		},
		"error/server url": {
			CTX:        context.Background(),
			StatusCode: http.StatusBadGateway,

			Token:     "token",
			ServerURL: "%%%",

			ErrorAssertionFunc: func(t assert.TestingT, err error, i ...interface{}) bool {
				var urlError *url.Error
				return assert.ErrorAs(t, err, &urlError) && assert.Equal(t, "parse", urlError.Op)
			},
		},
	} {
		tc := test
		t.Run(name, func(t *testing.T) {
			c := newTestClient(t, func(
				t *testing.T,
				req *http.Request,
			) (*http.Response, error) {
				assert.Equal(t, tc.CTX, req.Context())
				assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
				assert.Equal(t, apiURLAuth, req.URL.Path)
				assert.Equal(t, http.MethodPost, req.Method)
				assert.Contains(t, req.Header, "X-Men-Signature")
				w := httptest.NewRecorder()
				w.Header().Set("Content-Type", "application/jwt")
				w.WriteHeader(tc.StatusCode)
				w.Write([]byte(tc.Token))

				return w.Result(), tc.RoundTripError
			}, func(h *HTTPClient) {
				if tc.ServerURL != "" {
					h.serverURL = tc.ServerURL
				}
				if tc.Signer != nil {
					h.PrivateKey = tc.Signer
				}
			})
			authz, err := c.Authenticate(tc.CTX)
			if tc.ErrorAssertionFunc != nil {
				tc.ErrorAssertionFunc(t, err)
			} else {
				assert.NoError(t, err)
				if assert.NotNil(t, authz) {
					assert.Equal(t, tc.Token, authz.Token)
				}
			}
		})
	}

}

func TestSendInventory(t *testing.T) {
	t.Parallel()

	var internalError = errors.New("internal error")

	type testCase struct {
		CTX            context.Context
		StatusCode     int
		RoundTripError error

		Inventory api.Inventory
		Authz     *api.Authz

		assert.ErrorAssertionFunc
	}

	for name, test := range map[string]testCase{
		"ok": {
			CTX:        context.Background(),
			StatusCode: 204,
			Authz: &api.Authz{
				ServerURL: "http+testing://localhost:1234",
				Token:     "token",
			},
		},
		"error/roundtrip": {
			CTX:        context.Background(),
			StatusCode: 500,
			Authz: &api.Authz{
				ServerURL: "http+testing://localhost:1234",
				Token:     "token",
			},
			RoundTripError: internalError,
			ErrorAssertionFunc: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, internalError, i...)
			},
		},
		"error/bad status code": {
			CTX:        context.Background(),
			StatusCode: http.StatusInternalServerError,
			Authz: &api.Authz{
				ServerURL: "http+testing://localhost:1234",
				Token:     "token",
			},
			ErrorAssertionFunc: func(t assert.TestingT, err error, i ...interface{}) bool {
				var apiErr *api.Error
				return assert.ErrorAs(t, err, &apiErr) && assert.Equal(t, http.StatusInternalServerError, apiErr.Code)
			},
		},
		"error/zero auth": {
			CTX:        context.Background(),
			StatusCode: 204,
			ErrorAssertionFunc: func(t assert.TestingT, err error, i ...interface{}) bool {
				var apiErr *api.Error
				return assert.ErrorAs(t, err, &apiErr) && assert.Equal(t, http.StatusUnauthorized, apiErr.Code)
			},
		},
		"error/bad URL": {
			CTX:        context.Background(),
			StatusCode: 500,
			Authz: &api.Authz{
				ServerURL: "%%%",
				Token:     "token",
			},
			ErrorAssertionFunc: func(t assert.TestingT, err error, i ...interface{}) bool {
				var urlError *url.Error
				return assert.ErrorAs(t, err, &urlError) && assert.Equal(t, "parse", urlError.Op)
			},
		},
	} {
		tc := test
		t.Run(name, func(t *testing.T) {
			c := newTestClient(t, func(
				t *testing.T,
				req *http.Request,
			) (*http.Response, error) {
				assert.Equal(t, tc.CTX, req.Context())
				assert.Equal(t, tc.Authz.Token, strings.TrimPrefix(
					req.Header.Get("Authorization"), "Bearer "),
				)
				assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
				assert.Equal(t, apiURLInventory, req.URL.Path)
				assert.Equal(t, http.MethodPut, req.Method)
				w := httptest.NewRecorder()
				w.WriteHeader(tc.StatusCode)

				return w.Result(), tc.RoundTripError
			}, func(h *HTTPClient) {
				if tc.Authz != nil {
					h.serverURL = tc.Authz.ServerURL
				}
			})
			err := c.SendInventory(tc.CTX, tc.Authz, tc.Inventory)
			if tc.ErrorAssertionFunc != nil {
				tc.ErrorAssertionFunc(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}

}
