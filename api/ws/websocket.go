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

	"github.com/mendersoftware/go-lib-micro/ws"
	"github.com/vmihailenco/msgpack/v5"
	"nhooyr.io/websocket"

	"github.com/northerntechhq/nt-connect/api"
)

type socket struct {
	msgChan  chan ws.ProtoMsg
	err      error
	pongChan chan struct{}
	done     chan struct{}
	mu       sync.Mutex
	writeMu  sync.Mutex
	conn     *websocket.Conn
}

func (sock *socket) ReceiveChan() <-chan ws.ProtoMsg {
	return sock.msgChan
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
		err = sock.conn.Write(sock, websocket.MessageBinary, b)
	}
	return err
}

func (sock *socket) term(err error) bool {
	sock.mu.Lock()
	defer sock.mu.Unlock()
	select {
	case <-sock.done:
		return true
	default:
		sock.err = err
		close(sock.done)
	}
	return false
}

func (sock *socket) Close() error {
	if !sock.term(nil) {
		return sock.conn.Close(websocket.StatusNormalClosure, "disconnecting")
	}
	return nil
}

func (sock *socket) receiver() {
	defer sock.Close()
	defer close(sock.msgChan)
	for {
		var msg ws.ProtoMsg
		_, r, err := sock.conn.Reader(sock)
		if err != nil {
			sock.term(err)
			return
		}
		err = msgpack.NewDecoder(r).
			Decode(&msg)
		if err != nil {
			sock.term(err)
			return
		}
		select {
		case <-sock.done:
			return
		case sock.msgChan <- msg:
		}
	}
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
			err := sock.conn.Ping(sock)
			if err != nil {
				sock.term(err)
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
			sock.term(ErrPongDeadline)
			return
		}
	}
}

func newSocket(conn *websocket.Conn) (*socket, error) {
	sock := &socket{
		msgChan:  make(chan ws.ProtoMsg),
		pongChan: make(chan struct{}, 1),
		done:     make(chan struct{}),
		conn:     conn,
	}
	err := sock.conn.Ping(sock)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}
	go sock.pinger()
	go sock.receiver()
	return sock, nil
}

// Done extends the socket to use itself as a Context
func (sock *socket) Done() <-chan struct{} {
	return sock.done
}

// Err extends the socket to use itself as a Context
func (sock *socket) Err() error {
	if sock.err != nil {
		return sock.err
	}
	select {
	case <-sock.done:
		return context.Canceled
	default:
		return nil
	}
}

// Deadline extends the socket to use itself as a Context
func (sock *socket) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

// Value extends the socket to use itself as a Context
func (sock *socket) Value(key any) any {
	return nil
}

// Client implements only parts of the api.Client interface
type Client struct{}

func NewClient(tlsConfig *tls.Config) api.SocketClient {
	return &Client{}
}

func (c *Client) OpenSocket(ctx context.Context, authz *api.Authz) (api.Socket, error) {
	const APIURLConnect = "/api/devices/v1/deviceconnect/connect"
	url := strings.TrimRight(authz.ServerURL, "/") + APIURLConnect
	if strings.HasPrefix(url, "http") {
		url = strings.Replace(url, "http", "ws", 1)
	}
	//nolint: bodyclose
	conn, rsp, err := websocket.Dial(ctx,
		url,
		&websocket.DialOptions{HTTPHeader: http.Header{
			"Authorization": []string{"Bearer " + authz.Token},
		}},
	)
	if err != nil {
		return nil, err
	}
	if rsp.StatusCode >= 300 {
		return nil, &api.Error{Code: rsp.StatusCode}
	}
	return newSocket(conn)
}
