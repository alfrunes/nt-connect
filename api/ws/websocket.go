// Copyright 2023 Northern.tech AS
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

package ws

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mendersoftware/go-lib-micro/ws"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/northerntechhq/nt-connect/api"
)

type socket struct {
	msgChan  chan ws.ProtoMsg
	errChan  chan error
	pongChan chan struct{}
	done     chan struct{}
	mu       sync.Mutex
	writeMu  sync.Mutex
	conn     *websocket.Conn
}

func (sock *socket) ReceiveChan() <-chan ws.ProtoMsg {
	return sock.msgChan
}
func (sock *socket) ErrorChan() <-chan error {
	return sock.errChan
}

var (
	ErrClosed       = errors.New("closed")
	ErrPongDeadline = errors.New("deadline exceeded waiting for pong message")
)

func (sock *socket) Send(msg ws.ProtoMsg) error {
	var (
		err error
		b   []byte
	)
	select {
	case <-sock.done:
		return ErrClosed

	default:
		b, err = msgpack.Marshal(msg)
		if err != nil {
			return err
		}
		sock.writeMu.Lock()
		defer sock.writeMu.Unlock()
		err = sock.conn.WriteMessage(websocket.BinaryMessage, b)
	}
	return err
}

func (sock *socket) term() bool {
	sock.mu.Lock()
	defer sock.mu.Unlock()
	select {
	case <-sock.done:
		return true
	default:
		close(sock.done)
	}
	return false
}

func (sock *socket) Close() error {
	if !sock.term() {
		return sock.conn.Close()
	}
	return nil
}

func (sock *socket) pushError(err error) {
	select {
	case sock.errChan <- err:
	default:
	}
}

func (sock *socket) receiver() {
	defer sock.Close()
	defer close(sock.msgChan)
	for {
		var msg ws.ProtoMsg
		_, r, err := sock.conn.NextReader()
		if err != nil {
			sock.pushError(err)
			return
		}
		err = msgpack.NewDecoder(r).
			Decode(&msg)
		if err != nil {
			sock.pushError(err)
		}
		select {
		case <-sock.done:
			return
		case sock.msgChan <- msg:
		}
	}
}

func (sock *socket) ping() error {
	sock.writeMu.Lock()
	defer sock.writeMu.Unlock()
	return sock.conn.WriteControl(
		websocket.PingMessage,
		nil,
		time.Time{},
	)
}

func (sock *socket) pinger() {
	ticker := time.NewTicker(time.Minute * 30)
	timer := time.NewTimer(0)
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	defer sock.Close()
	for {
		select {
		case <-sock.done:
			return
		case <-ticker.C:
			err := sock.ping()
			if err != nil {
				sock.pushError(err)
				return
			}
			// Generous deadline of 30 secs
			timer.Reset(time.Second * 30)
		case <-sock.pongChan:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
			sock.pushError(ErrPongDeadline)
			return
		}
	}
}

func newSocket(conn *websocket.Conn) (*socket, error) {
	sock := &socket{
		msgChan:  make(chan ws.ProtoMsg),
		errChan:  make(chan error, 1),
		pongChan: make(chan struct{}, 1),
		done:     make(chan struct{}),
		conn:     conn,
	}
	conn.SetPongHandler(func(appData string) error {
		select {
		case sock.pongChan <- struct{}{}:
		default:
		}
		return nil
	})
	err := sock.ping()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}
	go sock.pinger()
	go sock.receiver()
	return sock, nil
}

// Client implements only parts of the api.Client interface
type Client websocket.Dialer

func NewClient(tlsConfig *tls.Config) *Client {
	return (*Client)(&websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		TLSClientConfig:  tlsConfig.Clone(),
		HandshakeTimeout: time.Minute,
	})
}

func (c *Client) OpenSocket(ctx context.Context, authz *api.Authz) (api.Socket, error) {
	const APIURLConnect = "/api/devices/v1/deviceconnect/connect"
	url := strings.TrimRight(authz.ServerURL, "/") + APIURLConnect
	if strings.HasPrefix(url, "http") {
		url = strings.Replace(url, "http", "ws", 1)
	}
	conn, rsp, err := (*websocket.Dialer)(c).DialContext(
		ctx, url, http.Header{
			"Authorization": []string{"Bearer " + authz.Token},
		},
	)
	if err != nil {
		return nil, err
	}
	if rsp.Body != nil {
		_ = rsp.Body.Close()
	}
	if rsp.StatusCode >= 300 {
		return nil, &api.Error{Code: rsp.StatusCode}
	}
	return newSocket(conn)
}
