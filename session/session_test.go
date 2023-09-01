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
package session

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/mendersoftware/go-lib-micro/ws"
	wsshell "github.com/mendersoftware/go-lib-micro/ws/shell"

	"github.com/northerntechhq/nt-connect/api"
	"github.com/northerntechhq/nt-connect/procps"
)

type echoHandler struct{}

func (h echoHandler) ServeProtoMsg(msg *ws.ProtoMsg, w api.Sender) {
	_ = w.Send(*msg)
}

func (h echoHandler) Close() error {
	return nil
}

type testWriter struct {
	Called   chan struct{}
	Messages []ws.ProtoMsg
	err      error
}

type senderMock struct {
	SendChan chan ws.ProtoMsg
	closed   chan struct{}
	mu       sync.Mutex
}

func newDiscardSender(t *testing.T) api.Sender {
	ret := &senderMock{
		SendChan: make(chan ws.ProtoMsg, 1),
		closed:   make(chan struct{}),
	}
	go func() {
		for {
			select {
			case msg := <-ret.SendChan:
				t.Logf("recevied message: proto=%d, type=%s, len(body)=%d",
					msg.Header.Proto, msg.Header.MsgType, len(msg.Body))
			case <-ret.closed:
				return
			}
		}
	}()
	t.Cleanup(func() {
		ret.Close()
	})
	return ret
}

func (s *senderMock) Send(msg ws.ProtoMsg) error {
	select {
	case s.SendChan <- msg:
	case <-s.closed:
		return io.ErrClosedPipe
	}
	return nil
}

func (s *senderMock) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.closed:

	default:
		close(s.closed)
	}
	return nil
}

func NewTestWriter(err error) *testWriter {
	return &testWriter{
		Called: make(chan struct{}, 1),
		err:    err,
	}
}

func (w *testWriter) Send(msg ws.ProtoMsg) error {
	select {
	case w.Called <- struct{}{}:
	default:
	}
	w.Messages = append(w.Messages, msg)
	return w.err
}

func TestSessionListen(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		Name string

		Config
		SessionID  string
		Routes     ProtoRoutes
		WriteError error

		ClientFunc func(msgChan chan<- *ws.ProtoMsg)
		Responses  []ws.ProtoMsg
	}{{
		Name: "ok",

		SessionID: "1234",

		Routes: ProtoRoutes{
			ws.ProtoType(0x1234): func() SessionHandler {
				return new(echoHandler)
			},
		},

		Config: Config{
			IdleTimeout: time.Second * 10,
		},

		ClientFunc: func(msgChan chan<- *ws.ProtoMsg) {
			msgChan <- &ws.ProtoMsg{
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoType(0x1234),
					MsgType:   "testing123",
					SessionID: "1234",
				},
			}
			close(msgChan)
		},
		Responses: []ws.ProtoMsg{{
			Header: ws.ProtoHdr{
				Proto:     ws.ProtoType(0x1234),
				MsgType:   "testing123",
				SessionID: "1234",
			},
		}},
	}, {
		Name: "ok, ping/pong -> close",

		SessionID: "1234",

		Config: Config{
			IdleTimeout: time.Second * 10,
		},

		ClientFunc: func(msgChan chan<- *ws.ProtoMsg) {
			msgChan <- &ws.ProtoMsg{
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoTypeControl,
					MsgType:   ws.MessageTypePing,
					SessionID: "1234",
				},
			}
			msgChan <- &ws.ProtoMsg{
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoTypeControl,
					MsgType:   ws.MessageTypeClose,
					SessionID: "1234",
				},
			}
		},
		Responses: []ws.ProtoMsg{{
			Header: ws.ProtoHdr{
				Proto:     ws.ProtoTypeControl,
				MsgType:   ws.MessageTypePong,
				SessionID: "1234",
			},
		}},
	}, {
		Name: "ok, handshake",

		SessionID: "1234",
		Config: Config{
			IdleTimeout: time.Second * 10,
		},
		Routes: ProtoRoutes{
			ws.ProtoType(0x1234): func() SessionHandler {
				return new(echoHandler)
			},
		},

		ClientFunc: func(msgChan chan<- *ws.ProtoMsg) {
			b, _ := msgpack.Marshal(ws.Open{
				Versions: []int{ws.ProtocolVersion},
			})
			msgChan <- &ws.ProtoMsg{
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoTypeControl,
					MsgType:   ws.MessageTypeOpen,
					SessionID: "1234",
				},
				Body: b,
			}
			close(msgChan)
		},

		Responses: func() []ws.ProtoMsg {
			b, _ := msgpack.Marshal(ws.Accept{
				Version:   ws.ProtocolVersion,
				Protocols: []ws.ProtoType{0x1234},
			})
			return []ws.ProtoMsg{{
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoTypeControl,
					MsgType:   ws.MessageTypeAccept,
					SessionID: "1234",
				},
				Body: b,
			}}
		}(),
	}, {
		Name: "error, protocol version not supported",

		SessionID: "1234",
		Config: Config{
			IdleTimeout: time.Second * 10,
		},

		ClientFunc: func(msgChan chan<- *ws.ProtoMsg) {
			b, _ := msgpack.Marshal(ws.Open{
				Versions: []int{ws.ProtocolVersion + 1},
			})
			msgChan <- &ws.ProtoMsg{
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoTypeControl,
					MsgType:   ws.MessageTypeOpen,
					SessionID: "1234",
				},
				Body: b,
			}
			close(msgChan)
		},

		Responses: func() []ws.ProtoMsg {
			b, _ := msgpack.Marshal(ws.Error{
				Error: fmt.Sprintf(
					"handshake rejected: require version %d",
					ws.ProtocolVersion,
				),
				MessageProto: ws.ProtoTypeControl,
				MessageType:  ws.MessageTypeOpen,
				Close:        true,
			})
			return []ws.ProtoMsg{{
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoTypeControl,
					MsgType:   ws.MessageTypeError,
					SessionID: "1234",
				},
				Body: b,
			}}
		}(),
	}, {
		Name: "error, bad handshake schema",

		SessionID: "1234",
		Config: Config{
			IdleTimeout: time.Second * 10,
		},

		ClientFunc: func(msgChan chan<- *ws.ProtoMsg) {
			msgChan <- &ws.ProtoMsg{
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoTypeControl,
					MsgType:   ws.MessageTypeOpen,
					SessionID: "1234",
				},
				Body: []byte("foobar"),
			}
			close(msgChan)
		},

		Responses: func() []ws.ProtoMsg {
			b, _ := msgpack.Marshal(ws.Error{
				Error: "failed to decode handshake request: " +
					"msgpack: unexpected code=66 decoding map length",
				MessageProto: ws.ProtoTypeControl,
				MessageType:  ws.MessageTypeOpen,
				Close:        true,
			})
			return []ws.ProtoMsg{{
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoTypeControl,
					MsgType:   ws.MessageTypeError,
					SessionID: "1234",
				},
				Body: b,
			}}
		}(),
	}, {
		Name: "ok, accepted",

		SessionID: "1234",
		Config: Config{
			IdleTimeout: time.Second * 10,
		},

		ClientFunc: func(msgChan chan<- *ws.ProtoMsg) {
			b, _ := msgpack.Marshal(ws.Accept{
				Version:   ws.ProtocolVersion,
				Protocols: []ws.ProtoType{0x1234},
			})
			msgChan <- &ws.ProtoMsg{
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoTypeControl,
					MsgType:   ws.MessageTypeAccept,
					SessionID: "1234",
				},
				Body: b,
			}
			close(msgChan)
		},
		// No responses expected in return
	}, {
		Name: "error, malformed handshake response",

		SessionID: "1234",
		Config: Config{
			IdleTimeout: time.Second * 10,
		},

		ClientFunc: func(msgChan chan<- *ws.ProtoMsg) {
			msgChan <- &ws.ProtoMsg{
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoTypeControl,
					MsgType:   ws.MessageTypeAccept,
					SessionID: "1234",
				},
				Body: []byte("foobar"),
			}
			close(msgChan)
		},

		Responses: func() []ws.ProtoMsg {
			b, _ := msgpack.Marshal(ws.Error{
				Error: "malformed handshake response: " +
					"msgpack: unexpected code=66 decoding map length",
				MessageProto: ws.ProtoTypeControl,
				MessageType:  ws.MessageTypeAccept,
				Close:        true,
			})
			return []ws.ProtoMsg{{
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoTypeControl,
					MsgType:   ws.MessageTypeError,
					SessionID: "1234",
				},
				Body: b,
			}}
		}(),
	}, {
		Name: "error, invalid handshake version",

		SessionID: "1234",
		Config: Config{
			IdleTimeout: time.Second * 10,
		},

		ClientFunc: func(msgChan chan<- *ws.ProtoMsg) {
			b, _ := msgpack.Marshal(ws.Accept{
				Version:   ws.ProtocolVersion + 1,
				Protocols: []ws.ProtoType{0x1234},
			})
			msgChan <- &ws.ProtoMsg{
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoTypeControl,
					MsgType:   ws.MessageTypeAccept,
					SessionID: "1234",
				},
				Body: b,
			}
			close(msgChan)
		},

		Responses: func() []ws.ProtoMsg {
			b, _ := msgpack.Marshal(ws.Error{
				Error: fmt.Sprintf(
					"unsupported protocol version %d: require version %d",
					ws.ProtocolVersion+1, ws.ProtocolVersion,
				),
				MessageProto: ws.ProtoTypeControl,
				MessageType:  ws.MessageTypeAccept,
				Close:        true,
			})
			return []ws.ProtoMsg{{
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoTypeControl,
					MsgType:   ws.MessageTypeError,
					SessionID: "1234",
				},
				Body: b,
			}}
		}(),
	}, {
		Name: "error, control message not understood",

		SessionID: "1234",

		Config: Config{
			IdleTimeout: time.Second * 10,
		},

		ClientFunc: func(msgChan chan<- *ws.ProtoMsg) {
			msgChan <- &ws.ProtoMsg{
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoTypeControl,
					MsgType:   "ehlo?",
					SessionID: "1234",
				},
			}
			close(msgChan)
		},
		Responses: func() []ws.ProtoMsg {
			errMsg := ws.Error{
				Error: "session: control type message not understood: 'ehlo?'",

				MessageProto: ws.ProtoTypeControl,
				MessageType:  "ehlo?",
			}
			b, _ := msgpack.Marshal(errMsg)
			return []ws.ProtoMsg{{
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoTypeControl,
					MsgType:   ws.MessageTypeError,
					SessionID: "1234",
				},
				Body: b,
			}}
		}(),
	}, {
		Name: "error, bad protocol -> close error",

		SessionID: "1234",

		Config: Config{
			IdleTimeout: time.Second * 10,
		},

		ClientFunc: func(msgChan chan<- *ws.ProtoMsg) {
			msgChan <- &ws.ProtoMsg{
				Header: ws.ProtoHdr{
					Proto:     0,
					MsgType:   "msgtyp",
					SessionID: "1234",
					Properties: map[string]interface{}{
						"msgid": "123456",
					},
				},
			}
			errMsg := ws.Error{
				Error: "dunno what to do next...",
				Close: true,
			}
			b, _ := msgpack.Marshal(errMsg)
			msgChan <- &ws.ProtoMsg{
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoTypeControl,
					MsgType:   ws.MessageTypeError,
					SessionID: "1234",
				},
				Body: b,
			}
		},
		Responses: func() []ws.ProtoMsg {
			errMsg := ws.Error{
				Error:        "no handler registered for protocol: 0x0000",
				MessageProto: 0,
				MessageType:  "msgtyp",
				MessageID:    "123456",
			}
			b, _ := msgpack.Marshal(errMsg)
			return []ws.ProtoMsg{{
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoTypeControl,
					MsgType:   ws.MessageTypeError,
					SessionID: "1234",
				},
				Body: b,
			}}
		}(),
	}, {
		Name: "error, session timeout",

		SessionID: "1234",

		Config: Config{
			IdleTimeout: time.Second / 4,
		},

		Responses: func() []ws.ProtoMsg {
			errMsg := ws.Error{
				Error: "session timeout",
				Close: true,
			}
			b, _ := msgpack.Marshal(errMsg)
			return []ws.ProtoMsg{{
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoTypeControl,
					MsgType:   ws.MessageTypePing,
					SessionID: "1234",
				},
			}, {
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoTypeControl,
					MsgType:   ws.MessageTypeError,
					SessionID: "1234",
				},
				Body: b,
			}}
		}(),
	}, {
		Name: "error, ping write error",

		SessionID: "1234",
		Config: Config{
			IdleTimeout: time.Second / 4,
		},
		WriteError: errors.New("this is bad!"),

		Responses: []ws.ProtoMsg{{
			Header: ws.ProtoHdr{
				Proto:     ws.ProtoTypeControl,
				MsgType:   ws.MessageTypePing,
				SessionID: "1234",
			},
		}},
	}, {
		Name: "error, write error",

		SessionID: "1234",
		Config: Config{
			IdleTimeout: time.Second,
		},
		WriteError: errors.New("this is bad!"),

		ClientFunc: func(msgChan chan<- *ws.ProtoMsg) {
			msgChan <- &ws.ProtoMsg{
				Header: ws.ProtoHdr{
					Proto: 0x1234,
				},
			}
			close(msgChan)
		},
		Responses: func() []ws.ProtoMsg {
			b, _ := msgpack.Marshal(ws.Error{
				Error:        "no handler registered for protocol: 0x1234",
				MessageProto: ws.ProtoType(0x1234),
			})
			return []ws.ProtoMsg{{
				Header: ws.ProtoHdr{
					Proto:     ws.ProtoTypeControl,
					MsgType:   ws.MessageTypeError,
					SessionID: "1234",
				},
				Body: b,
			}}
		}(),
	}}
	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			w := NewTestWriter(tc.WriteError)
			msgChan := make(chan *ws.ProtoMsg)
			sess := New(
				tc.SessionID, msgChan,
				w, tc.Routes, tc.Config,
			)
			go sess.ListenAndServe()
			if tc.ClientFunc != nil {
				tc.ClientFunc(sess.MsgChan())
			}
			select {
			case <-sess.Done():
				assert.Equal(t, tc.Responses, w.Messages)
			case <-time.After(time.Second * 10):
				panic("[PROGERR] test case timeout")
			}
		})
	}
}

// Unit tests for shell.go consider moving into shell_test.go

func TestMenderShellStartStopShell(t *testing.T) {
	MaxUserSessions = 2

	currentUser, err := user.Current()
	if err != nil {
		t.Errorf("cant get current user: %s", err.Error())
		t.FailNow()
		return
	}
	uid, err := strconv.ParseUint(currentUser.Uid, 10, 32)
	if err != nil {
		t.Errorf("cant get current uid: %s", err.Error())
		t.FailNow()
		return
	}

	gid, err := strconv.ParseUint(currentUser.Gid, 10, 32)
	if err != nil {
		t.Errorf("cant get current gid: %s", err.Error())
		t.FailNow()
		return
	}
	sender := newDiscardSender(t)

	s, err := NewMenderShellSession(sender, "c4993deb-26b4-4c58-aaee-fd0c9e694328", "user-id-f435678-f4567ff", defaultSessionExpiredTimeout, NoExpirationTimeout)
	if err != nil {
		t.Errorf("unexpected error creating session: %s", err.Error())
		t.FailNow()
	}

	err = s.StartShell(sender, s.GetId(), MenderShellTerminalSettings{
		Uid:            uint32(uid),
		Gid:            uint32(gid),
		Shell:          "/bin/sh",
		TerminalString: "xterm-256color",
		Height:         40,
		Width:          80,
	})
	if err != nil {
		t.Errorf("unexpected error starting shell: %s", err.Error())
		t.FailNow()
	}
	t.Logf("created session:\n id:%s,\n createdAt:%s,\n expiresAt:%s\n now:%s",
		s.id,
		s.createdAt.Format(defaultTimeFormat),
		s.expiresAt.Format(defaultTimeFormat),
		time.Now().Format(defaultTimeFormat))
	assert.NoError(t, err)
	assert.True(t, procps.ProcessExists(s.shellPid))
	assert.Equal(t, s.status, s.GetStatus())
	assert.Equal(t, s.GetStatus(), ActiveSession)
	assert.True(t, s.GetExpiresAtFmt() != "")
	assert.True(t, s.GetStartedAtFmt() != "")
	assert.True(t, s.GetActiveAtFmt() != "")
	nowUpToHours := strings.Split(time.Now().UTC().Format(defaultTimeFormat), ":")[0]
	nowUpToHoursExpires := strings.Split(time.Now().UTC().Add(defaultSessionExpiredTimeout).Format(defaultTimeFormat), ":")[0]
	assert.Equal(t, strings.Split(s.GetExpiresAtFmt(), ":")[0], nowUpToHoursExpires)
	assert.Equal(t, strings.Split(s.GetStartedAtFmt(), ":")[0], nowUpToHours)
	assert.Equal(t, strings.Split(s.GetActiveAtFmt(), ":")[0], nowUpToHours)
	assert.Equal(t, "/bin/sh", s.GetShellCommandPath())

	sNew, err := NewMenderShellSession(sender, "c4993deb-26b4-4c58-aaee-fd0c9e694328", "user-id-f435678-f4567ff", defaultSessionExpiredTimeout, NoExpirationTimeout)
	if err != nil {
		t.Errorf("unexpected error creating session: %s", err.Error())
		t.FailNow()
	}
	err = sNew.StartShell(sender, sNew.GetId(), MenderShellTerminalSettings{
		Uid:            uint32(uid),
		Gid:            uint32(gid),
		Shell:          "/bin/sh",
		TerminalString: "xterm-256color",
		Height:         40,
		Width:          80,
	})
	if err != nil {
		t.Errorf("unexpected error starting shell: %s", err.Error())
		t.FailNow()
	}
	assert.NoError(t, err)
	assert.True(t, procps.ProcessExists(s.shellPid))

	err = s.StopShell()
	if err != nil {
		assert.Equal(t, err.Error(), "error waiting for the process: signal: interrupt")
	}
	assert.False(t, procps.ProcessExists(s.shellPid))

	count, err := MenderShellStopByUserId("user-id-f435678-f4567ff")
	assert.NoError(t, err)
	assert.Equal(t, uint(2), count) //the reason for 2 here: s.StopShell does not intrinsically remove the session

	count, err = MenderShellStopByUserId("not-really-there")
	assert.Error(t, err)
	assert.Equal(t, uint(0), count)
}

func TestMenderShellCommand(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Errorf("cant get current user: %s", err.Error())
		return
	}
	uid, err := strconv.ParseUint(currentUser.Uid, 10, 32)
	if err != nil {
		t.Errorf("cant get current uid: %s", err.Error())
		return
	}

	gid, err := strconv.ParseUint(currentUser.Gid, 10, 32)
	if err != nil {
		t.Errorf("cant get current gid: %s", err.Error())
		return
	}

	sender := newDiscardSender(t)

	s, err := NewMenderShellSession(sender, "c4993deb-26b4-4c58-aaee-fd0c9e694328", uuid.NewV4().String(), defaultSessionExpiredTimeout, NoExpirationTimeout)
	if err != nil {
		t.Errorf("unexpected error creating shell session: %s", err.Error())
		t.FailNow()
	}
	err = s.StartShell(sender, s.GetId(), MenderShellTerminalSettings{
		Uid:            uint32(uid),
		Gid:            uint32(gid),
		Shell:          "/bin/sh",
		TerminalString: "xterm-256color",
		Height:         40,
		Width:          80,
	})
	if err != nil {
		t.Errorf("failed to start shell: %s", err.Error())
		t.FailNow()
	}
	assert.NoError(t, err)
	assert.True(t, procps.ProcessExists(s.shellPid))
	err = s.ShellCommand(&ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypeShell,
			MsgType:   wsshell.MessageTypeShellCommand,
			SessionID: s.GetId(),
			Properties: map[string]interface{}{
				"status": wsshell.NormalMessage,
			},
		},
		Body: []byte("echo ok;\n"),
	})
	assert.NoError(t, err)

	//close terminal controlling handle, for error from inside ShellCommand
	s.pseudoTTY.Close()
	err = s.ShellCommand(&ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypeShell,
			MsgType:   wsshell.MessageTypeShellCommand,
			SessionID: s.GetId(),
			Properties: map[string]interface{}{
				"status": wsshell.NormalMessage,
			},
		},
		Body: []byte("echo ok;\n"),
	})
	assert.Error(t, err)
}

func TestMenderShellShellAlreadyStartedFailedToStart(t *testing.T) {

	sender := newDiscardSender(t)
	MaxUserSessions = 2
	currentUser, err := user.Current()
	if err != nil {
		t.Errorf("cant get current user: %s", err.Error())
		return
	}
	uid, err := strconv.ParseUint(currentUser.Uid, 10, 32)
	if err != nil {
		t.Errorf("cant get current uid: %s", err.Error())
		return
	}

	gid, err := strconv.ParseUint(currentUser.Gid, 10, 32)
	if err != nil {
		t.Errorf("cant get current gid: %s", err.Error())
		return
	}

	userId := uuid.NewV4().String()
	s, err := NewMenderShellSession(sender, "c4993deb-26b4-4c58-aaee-fd0c9e694328", userId, defaultSessionExpiredTimeout, NoExpirationTimeout)
	if err != nil {
		t.Errorf("unexpected error creating shell session: %s", err.Error())
		t.FailNow()
	}
	err = s.StartShell(sender, s.GetId(), MenderShellTerminalSettings{
		Uid:            uint32(uid),
		Gid:            uint32(gid),
		Shell:          "/bin/sh",
		TerminalString: "xterm-256color",
		Height:         40,
		Width:          80,
	})
	if err != nil {
		t.Errorf("failed to start shell: %s", err.Error())
		t.FailNow()
	}
	assert.NoError(t, err)
	assert.True(t, procps.ProcessExists(s.shellPid))

	err = s.StartShell(sender, s.GetId(), MenderShellTerminalSettings{
		Uid:            uint32(uid),
		Gid:            uint32(gid),
		Shell:          "/bin/sh",
		TerminalString: "xterm-256color",
		Height:         40,
		Width:          80,
	})
	assert.Error(t, err)
	assert.True(t, procps.ProcessExists(s.shellPid))

	sNew, err := NewMenderShellSession(sender, "c4993deb-26b4-4c58-aaee-fd0c9e694328", userId, defaultSessionExpiredTimeout, NoExpirationTimeout)
	if err != nil {
		t.Errorf("unexpected error creating shell session: %s", err.Error())
		t.FailNow()
	}
	err = sNew.StartShell(sender, sNew.GetId(), MenderShellTerminalSettings{
		Uid:            uint32(uid),
		Gid:            uint32(gid),
		Shell:          "thatissomethingelse/bin/sh",
		TerminalString: "xterm-256color",
		Height:         40,
		Width:          80,
	})
	assert.Error(t, err)
}

func TestMenderShellSessionExpire(t *testing.T) {
	sender := newDiscardSender(t)
	defaultSessionExpiredTimeout = 2

	s, err := NewMenderShellSession(sender, "c4993deb-26b4-4c58-aaee-fd0c9e694328", "user-id-f435678-f4567f2", defaultSessionExpiredTimeout, NoExpirationTimeout)
	if err != nil {
		t.Errorf("unexpected error creating shell session: %s", err.Error())
		t.FailNow()
	}
	err = s.StartShell(sender, s.GetId(), MenderShellTerminalSettings{
		Uid:            500,
		Gid:            501,
		Shell:          "/bin/sh",
		TerminalString: "xterm-256color",
		Height:         24,
		Width:          80,
	})
	assert.NoError(t, err)
	time.Sleep(2 * defaultSessionExpiredTimeout * time.Second)
	assert.True(t, s.IsExpired(false))
	assert.True(t, s.IsExpired(true))
}

func TestMenderShellSessionGetByUserId(t *testing.T) {
	sender := newDiscardSender(t)

	userId := "user-id-f431212-f4567ff"
	s, err := NewMenderShellSession(sender, "c4993deb-26b4-4c58-aaee-fd0c9e694328", userId, defaultSessionExpiredTimeout, NoExpirationTimeout)
	assert.NoError(t, err)

	anotherUserId := "user-id-f4433528-43b342b234b"
	anotherUserSession, err := NewMenderShellSession(sender, "c4993deb-26b4-4c58-aaee-fd0c9e694328", anotherUserId, defaultSessionExpiredTimeout, NoExpirationTimeout)
	assert.NoError(t, err)

	assert.NotEqual(t, anotherUserId, userId)

	userSessions := MenderShellSessionsGetByUserId(userId)
	assert.True(t, len(userSessions) > 0)
	assert.NotNil(t, userSessions[0])
	assert.True(t, userSessions[0].GetId() == s.id)
	assert.True(t, userSessions[0].GetShellPid() == s.shellPid)

	anotherUserSessions := MenderShellSessionsGetByUserId(anotherUserId)
	assert.True(t, len(anotherUserSessions) > 0)
	assert.NotNil(t, anotherUserSessions[0])
	assert.True(t, anotherUserSessions[0].GetId() == anotherUserSession.id)
	assert.True(t, anotherUserSessions[0].GetShellPid() == anotherUserSession.shellPid)

	userSessions = MenderShellSessionsGetByUserId(userId + "-different")
	assert.False(t, len(userSessions) > 0)

	anotherUserSessions = MenderShellSessionsGetByUserId(anotherUserId + "-different")
	assert.False(t, len(anotherUserSessions) > 0)
}

func TestMenderShellSessionGetById(t *testing.T) {
	MaxUserSessions = 2

	sender := newDiscardSender(t)

	userId := "user-id-8989-f431212-f4567ff"
	s, err := NewMenderShellSession(sender, "c4993deb-26b4-4c58-aaee-fd0c9e694328", userId, defaultSessionExpiredTimeout, NoExpirationTimeout)
	assert.NoError(t, err)
	r, err := NewMenderShellSession(sender, "c4993deb-26b4-4c58-aaee-fd0c9e694328", userId, defaultSessionExpiredTimeout, NoExpirationTimeout)
	assert.NoError(t, err)

	anotherUserId := "user-id-8989-f4433528-43b342b234b"
	anotherUserSession, err := NewMenderShellSession(sender, "c4993deb-26b4-4c58-aaee-fd0c9e694328", anotherUserId, defaultSessionExpiredTimeout, NoExpirationTimeout)
	assert.NoError(t, err)
	andAnotherUserSession, err := NewMenderShellSession(sender, "c4993deb-26b4-4c58-aaee-fd0c9e694328", anotherUserId, defaultSessionExpiredTimeout, NoExpirationTimeout)
	assert.NoError(t, err)

	assert.NotEqual(t, anotherUserId, userId)

	userSessions := MenderShellSessionsGetByUserId(userId)
	assert.True(t, len(userSessions) == 2)
	assert.NotNil(t, userSessions[0])
	assert.True(t, userSessions[0].GetId() == s.id)

	anotherUserSessions := MenderShellSessionsGetByUserId(anotherUserId)
	assert.True(t, len(anotherUserSessions) == 2)
	assert.NotNil(t, anotherUserSessions[0])
	assert.True(t, anotherUserSessions[0].GetId() == anotherUserSession.id)

	assert.NotNil(t, MenderShellSessionGetById(userSessions[0].GetId()))
	assert.NotNil(t, MenderShellSessionGetById(userSessions[1].GetId()))
	assert.NotNil(t, MenderShellSessionGetById(anotherUserSessions[0].GetId()))
	assert.NotNil(t, MenderShellSessionGetById(anotherUserSessions[1].GetId()))
	assert.Nil(t, MenderShellSessionGetById("not-really-there"))

	var ids []string

	ids = []string{anotherUserSession.id, andAnotherUserSession.id}
	assert.Contains(t, ids, MenderShellSessionGetById(anotherUserSessions[0].GetId()).id)
	assert.Contains(t, ids, MenderShellSessionGetById(anotherUserSessions[1].GetId()).id)
	ids = []string{s.id, r.id}
	assert.Contains(t, ids, MenderShellSessionGetById(userSessions[0].GetId()).id)
	assert.Contains(t, ids, MenderShellSessionGetById(userSessions[1].GetId()).id)
}

func TestMenderShellDeleteById(t *testing.T) {
	MaxUserSessions = 2
	sender := newDiscardSender(t)

	userId := "user-id-1212-8989-f431212-f4567ff"
	s, err := NewMenderShellSession(sender, uuid.NewV4().String(), userId, defaultSessionExpiredTimeout, NoExpirationTimeout)
	assert.NoError(t, err)
	r, err := NewMenderShellSession(sender, uuid.NewV4().String(), userId, defaultSessionExpiredTimeout, NoExpirationTimeout)
	assert.NoError(t, err)

	anotherUserId := "user-id-1212-8989-f4433528-43b342b234b"
	anotherUserSession, err := NewMenderShellSession(sender, uuid.NewV4().String(), anotherUserId, defaultSessionExpiredTimeout, NoExpirationTimeout)
	assert.NoError(t, err)
	assert.NotNil(t, anotherUserSession)
	andAnotherUserSession, err := NewMenderShellSession(sender, uuid.NewV4().String(), anotherUserId, defaultSessionExpiredTimeout, NoExpirationTimeout)
	assert.NoError(t, err)
	assert.NotNil(t, anotherUserSession)

	assert.NotNil(t, MenderShellSessionGetById(anotherUserSession.GetId()))
	assert.NotNil(t, MenderShellSessionGetById(andAnotherUserSession.GetId()))
	assert.NotNil(t, MenderShellSessionGetById(s.GetId()))
	assert.NotNil(t, MenderShellSessionGetById(r.GetId()))

	err = MenderShellDeleteById("not-really-here")
	assert.Error(t, err)

	err = MenderShellDeleteById(anotherUserSession.GetId())
	assert.NoError(t, err)
	assert.Nil(t, MenderShellSessionGetById(anotherUserSession.GetId()))
	assert.NotNil(t, MenderShellSessionGetById(andAnotherUserSession.GetId()))
	assert.NotNil(t, MenderShellSessionGetById(s.GetId()))
	assert.NotNil(t, MenderShellSessionGetById(r.GetId()))

	err = MenderShellDeleteById("not-really-here")
	assert.Error(t, err)

	err = MenderShellDeleteById(andAnotherUserSession.GetId())
	assert.NoError(t, err)
	assert.Nil(t, MenderShellSessionGetById(anotherUserSession.GetId()))
	assert.Nil(t, MenderShellSessionGetById(andAnotherUserSession.GetId()))
	assert.NotNil(t, MenderShellSessionGetById(s.GetId()))
	assert.NotNil(t, MenderShellSessionGetById(r.GetId()))

	err = MenderShellDeleteById(s.GetId())
	assert.NoError(t, err)
	assert.Nil(t, MenderShellSessionGetById(anotherUserSession.GetId()))
	assert.Nil(t, MenderShellSessionGetById(andAnotherUserSession.GetId()))
	assert.Nil(t, MenderShellSessionGetById(s.GetId()))
	assert.NotNil(t, MenderShellSessionGetById(r.GetId()))

	err = MenderShellDeleteById(r.GetId())
	assert.NoError(t, err)
	assert.Nil(t, MenderShellSessionGetById(anotherUserSession.GetId()))
	assert.Nil(t, MenderShellSessionGetById(andAnotherUserSession.GetId()))
	assert.Nil(t, MenderShellSessionGetById(s.GetId()))
	assert.Nil(t, MenderShellSessionGetById(r.GetId()))

	err = MenderShellDeleteById("not-really-here")
	assert.Error(t, err)
}

func TestMenderShellNewMenderShellSession(t *testing.T) {
	MaxUserSessions = 2
	sender := newDiscardSender(t)

	sessionsMap = map[string]*MenderShellSession{}
	sessionsByUserIdMap = map[string][]*MenderShellSession{}
	var (
		createdSessonsIds []string
		s                 *MenderShellSession
		err               error
	)
	userId := uuid.NewV4().String()
	for i := 0; i < MaxUserSessions; i++ {
		s, err = NewMenderShellSession(sender, uuid.NewV4().String(), userId, defaultSessionExpiredTimeout, NoExpirationTimeout)
		assert.NoError(t, err)
		assert.NotNil(t, s)
		createdSessonsIds = append(createdSessonsIds, s.id)
	}
	notFoundSession, err := NewMenderShellSession(sender, uuid.NewV4().String(), userId, defaultSessionExpiredTimeout, NoExpirationTimeout)
	assert.Error(t, err)
	assert.Nil(t, notFoundSession)

	sessionById := MenderShellSessionGetById(s.GetId())
	assert.NotNil(t, sessionById)
	assert.True(t, sessionById.id == s.GetId())

	count := MenderShellSessionGetCount()
	assert.Equal(t, MaxUserSessions, count)

	sessionsIds := MenderShellSessionGetSessionIds()
	assert.Equal(t, len(createdSessonsIds), len(sessionsIds))
	assert.ElementsMatch(t, createdSessonsIds, sessionsIds)
}

func TestMenderSessionTerminateExpired(t *testing.T) {
	defaultSessionExpiredTimeout = 8 * time.Second
	sessionsMap = map[string]*MenderShellSession{}
	sessionsByUserIdMap = map[string][]*MenderShellSession{}
	sender := newDiscardSender(t)

	s, err := NewMenderShellSession(sender, "c4993deb-26b4-4c58-aaee-fd0c9e694328", "user-id-f435678-f4567f2", defaultSessionExpiredTimeout, NoExpirationTimeout)
	if err != nil {
		t.Errorf("unexpected error creating shell session: %s", err.Error())
		t.FailNow()
	}
	t.Logf("created session:\n id:%s,\n createdAt:%s,\n expiresAt:%s\n now:%s",
		s.id,
		s.createdAt.Format("Mon Jan 2 15:04:05 -0700 MST 2006"),
		s.expiresAt.Format("Mon Jan 2 15:04:05 -0700 MST 2006"),
		time.Now().Format("Mon Jan 2 15:04:05 -0700 MST 2006"))
	err = s.StartShell(sender, s.GetId(), MenderShellTerminalSettings{
		Uid:            500,
		Gid:            501,
		Shell:          "/bin/sh",
		TerminalString: "xterm-256color",
		Height:         24,
		Width:          80,
	})
	assert.NoError(t, err)

	shells, sessions, total, err := MenderSessionTerminateExpired()
	assert.NoError(t, err)
	assert.Equal(t, 0, shells)
	assert.Equal(t, 0, sessions)
	assert.Equal(t, 0, total)

	time.Sleep(2 * defaultSessionExpiredTimeout)
	assert.True(t, s.IsExpired(false))

	shells, sessions, total, err = MenderSessionTerminateExpired()
	assert.NoError(t, err)
	assert.Equal(t, 1, shells)
	assert.Equal(t, 1, sessions)
	assert.Equal(t, 0, total)
	assert.True(t, !procps.ProcessExists(s.shellPid))
}

func TestMenderSessionTerminateAll(t *testing.T) {
	defaultSessionExpiredTimeout = 8 * time.Second
	sessionsMap = map[string]*MenderShellSession{}
	sessionsByUserIdMap = map[string][]*MenderShellSession{}
	sender := newDiscardSender(t)

	s0, err := NewMenderShellSession(sender, uuid.NewV4().String(), "user-id-f435678-f4567f2", defaultSessionExpiredTimeout, NoExpirationTimeout)
	if err != nil {
		t.Errorf("unexpected error creating shell session: %s", err.Error())
		t.FailNow()
	}
	t.Logf("created session:\n id:%s,\n createdAt:%s,\n expiresAt:%s\n now:%s",
		s0.id,
		s0.createdAt.Format("Mon Jan 2 15:04:05 -0700 MST 2006"),
		s0.expiresAt.Format("Mon Jan 2 15:04:05 -0700 MST 2006"),
		time.Now().Format("Mon Jan 2 15:04:05 -0700 MST 2006"))
	err = s0.StartShell(sender, s0.GetId(), MenderShellTerminalSettings{
		Uid:            500,
		Gid:            501,
		Shell:          "/bin/sh",
		TerminalString: "xterm-256color",
		Height:         24,
		Width:          80,
	})
	assert.NoError(t, err)

	s1, err := NewMenderShellSession(sender, uuid.NewV4().String(), "user-id-f435678-f4567f3", defaultSessionExpiredTimeout, NoExpirationTimeout)
	if err != nil {
		t.Errorf("unexpected error creating shell session: %s", err.Error())
		t.FailNow()
	}
	t.Logf("created session:\n id:%s,\n createdAt:%s,\n expiresAt:%s\n now:%s",
		s1.id,
		s1.createdAt.Format("Mon Jan 2 15:04:05 -0700 MST 2006"),
		s1.expiresAt.Format("Mon Jan 2 15:04:05 -0700 MST 2006"),
		time.Now().Format("Mon Jan 2 15:04:05 -0700 MST 2006"))
	err = s1.StartShell(sender, s1.GetId(), MenderShellTerminalSettings{
		Uid:            500,
		Gid:            501,
		Shell:          "/bin/sh",
		TerminalString: "xterm-256color",
		Height:         24,
		Width:          80,
	})
	assert.NoError(t, err)

	_, _, _ = MenderSessionTerminateAll()
	assert.NoError(t, err)
	assert.True(t, !procps.ProcessExists(s0.shellPid))
	assert.True(t, !procps.ProcessExists(s1.shellPid))
}

func TestMenderSessionTerminateIdle(t *testing.T) {
	defaultSessionExpiredTimeout = 255 * time.Second
	idleTimeOut := 4 * time.Second
	sessionsMap = map[string]*MenderShellSession{}
	sessionsByUserIdMap = map[string][]*MenderShellSession{}
	sender := newDiscardSender(t)

	s, err := NewMenderShellSession(sender, "c4993deb-26b4-4c58-aaee-fd0c9e694328", "user-id-f435678-f4567f2", NoExpirationTimeout, idleTimeOut)
	if err != nil {
		t.Errorf("unexpected error creating shell session: %s", err.Error())
		t.FailNow()
	}
	t.Logf("created session:\n id:%s,\n createdAt:%s,\n expiresAt:%s\n now:%s",
		s.id,
		s.createdAt.Format("Mon Jan 2 15:04:05 -0700 MST 2006"),
		s.expiresAt.Format("Mon Jan 2 15:04:05 -0700 MST 2006"),
		time.Now().Format("Mon Jan 2 15:04:05 -0700 MST 2006"))
	err = s.StartShell(sender, s.GetId(), MenderShellTerminalSettings{
		Uid:            500,
		Gid:            501,
		Shell:          "/bin/sh",
		TerminalString: "xterm-256color",
		Height:         24,
		Width:          80,
	})
	assert.NoError(t, err)

	go func(f *os.File) {
		for i := 0; i < 2*int(idleTimeOut.Seconds()); i++ {
			f.Write([]byte("echo;\n"))
			time.Sleep(time.Second)
		}
	}(s.pseudoTTY)

	shells, sessions, total, err := MenderSessionTerminateExpired()
	assert.NoError(t, err)
	assert.Equal(t, 0, shells)
	assert.Equal(t, 0, sessions)
	assert.Equal(t, 0, total)

	time.Sleep(2 * idleTimeOut)
	assert.True(t, s.IsExpired(false))

	shells, sessions, total, err = MenderSessionTerminateExpired()
	assert.NoError(t, err)
	assert.Equal(t, 1, shells)
	assert.Equal(t, 1, sessions)
	assert.Equal(t, 0, total)
	assert.True(t, !procps.ProcessExists(s.shellPid))
}

func TestMenderSessionTimeNow(t *testing.T) {
	assert.Equal(t, timeNow().Format(defaultTimeFormat), time.Now().UTC().Format(defaultTimeFormat))
}
