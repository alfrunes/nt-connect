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
	"errors"
	"io"
	"net/http"

	"github.com/northerntechhq/nt-connect/api"
)

type rtFunc func(req *http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type dummySockClient struct {
	sock api.Socket
	err  error
}

func (d dummySockClient) OpenSocket(ctx context.Context, authz *api.Authz) (api.Socket, error) {
	return d.sock, d.err
}

type badSigner struct{}

var badSignerError = errors.New("bad signer")

func (s badSigner) Public() crypto.PublicKey {
	return s
}

func (badSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, badSignerError
}
