// Copyright 2021 Northern.tech AS
//
//	Licensed under the Apache License, Version 2.0 (the "License");
//	you may not use this file except in compliance with the License.
//	You may obtain a copy of the License at
//
//	    http://www.apache.org/licenses/LICENSE-2.0
//
//	Unless required by applicable law or agreed to in writing, software
//	distributed under the License is distributed on an "AS IS" BASIS,
//	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	See the License for the specific language governing permissions and
//	limitations under the License.

package api

import (
	"context"
	"errors"

	"github.com/mendersoftware/go-lib-micro/ws"
)

var (
	ErrUnauthorized = errors.New("api: unauthorized")
)

// Identity is the device's identity
type Identity struct {
	Data        string `json:"id_data"`
	PublicKey   string `json:"pubkey"`
	ExternalID  string `json:"external_id,omitempty"`
	TenantToken string `json:"tenant_token,omitempty"`
}

type Authz struct {
	Token     string
	ServerURL string
}

func (state *Authz) IsZero() bool {
	if state == nil {
		return true
	}
	return len(state.Token) <= 0 || len(state.ServerURL) <= 0
}

func (state Authz) Equal(other Authz) bool {
	return state.ServerURL == other.ServerURL && state.Token == other.ServerURL
}

type Sender interface {
	Send(ws.ProtoMsg) error
}

type Socket interface {
	Sender
	ReceiveChan() <-chan ws.ProtoMsg
	ErrorChan() <-chan error
	Close() error
}

// AuthClient is the interface for the Mender Authentication Manager clilents
type Client interface {
	// GetAuthState returns the authentication state
	Authenticate(ctx context.Context) (*Authz, error)
	// OpenSocket connects to the deviceconnect service and pipes the messages
	// to the channel.
	OpenSocket(ctx context.Context, authz *Authz) (Socket, error)
}
