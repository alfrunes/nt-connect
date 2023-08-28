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
package app

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"os"
	"os/user"
	"strconv"
	"strings"
	"testing"
	"time"

	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mendersoftware/go-lib-micro/ws"
	wsshell "github.com/mendersoftware/go-lib-micro/ws/shell"

	"github.com/northerntechhq/nt-connect/api"
	"github.com/northerntechhq/nt-connect/config"
	"github.com/northerntechhq/nt-connect/session"
	sessmocks "github.com/northerntechhq/nt-connect/session/mocks"
)

func newTestDaemonWithConfig(t *testing.T, cfg *config.MenderShellConfig) (*Daemon, *SocketMock) {

	ctx := context.Background()
	authz := &api.Authz{
		Token:     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9Cg.eyJleHAiOiAxMjM0NTY3ODkwfQo.8QEZaUGzH5w",
		ServerURL: "http://localhost:12345",
	}
	sockMock := &SocketMock{
		RecvChan: make(chan ws.ProtoMsg, 10),
		SendChan: make(chan ws.ProtoMsg, 10),
		ErrChan:  make(chan error),
		closed:   make(chan struct{}),
	}
	apiMock := NewClient(t)
	apiMock.On("Authenticate", ctx).
		Return(authz, nil).
		Once().
		On("OpenSocket", ctx, authz).
		Return(sockMock, nil).
		Once()

	d := newDaemon(cfg)
	d.apiClient = apiMock
	go func() {
		if err := d.Run(); err != nil {
			t.Errorf("daemon exited with error: %s", err.Error())
		}
	}()
	t.Cleanup(d.StopDaemon)
	t.Cleanup(func() { apiMock.AssertExpectations(t) })
	return d, sockMock
}
func newTestDaemon(t *testing.T) (*Daemon, *SocketMock) {
	currentUser, err := user.Current()
	if err != nil {
		t.Errorf("cant get current user: %s", err.Error())
		t.FailNow()
	}
	return newTestDaemonWithConfig(t, &config.MenderShellConfig{
		MenderShellConfigFromFile: config.MenderShellConfigFromFile{
			ShellCommand: "/bin/sh",
			User:         currentUser.Username,
			Terminal: config.TerminalConfig{
				Width:  24,
				Height: 80,
			},
		},
	})
}

func TestMenderShellSessionStart(t *testing.T) {
	testData := "newShellTransaction." + strconv.Itoa(rand.Intn(6553600))
	tempFile, err := os.CreateTemp(t.TempDir(), "TestMenderShellExec")
	if err != nil {
		t.Error("cant create temp file")
		return
	}
	testFileNameTemporary := tempFile.Name()
	defer os.Remove(tempFile.Name())

	_, sockMock := newTestDaemon(t)
	go func() {
		for msg := range sockMock.SendChan {
			t.Logf("type=%s, session_id=%s, data=%s",
				msg.Header.MsgType, msg.Header.SessionID, string(msg.Body))
			if msg.Header.MsgType == wsshell.MessageTypeStopShell {
				sockMock.Close()
			}
		}
	}()
	msg := ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypeShell,
			MsgType:   wsshell.MessageTypeSpawnShell,
			SessionID: "c4993deb-26b4-4c58-aaee-fd0c9e694328",
			Properties: map[string]interface{}{
				propertyUserID:         "user-id-unit-tests-f6723467-561234ff",
				propertyTerminalWidth:  int64(80),
				propertyTerminalHeight: int64(60),
				"status":               wsshell.NormalMessage,
			},
		},
		Body: []byte{},
	}
	sockMock.RecvChan <- msg

	msg.Body = []byte("echo " + testData + " > " + testFileNameTemporary + "\n")
	msg.Header.MsgType = wsshell.MessageTypeShellCommand
	sockMock.RecvChan <- msg

	msg.Body = []byte("rm -f " + testFileNameTemporary + "\n")
	msg.Header.SessionID = "undefined-session-id"
	sockMock.RecvChan <- msg

	msg.Header.SessionID = "c4993deb-26b4-4c58-aaee-fd0c9e694328"
	msg.Body = []byte("thiscommand probably does not exist\n")
	sockMock.RecvChan <- msg

	msg.Body = []byte("thiscommand probably does not exist\n")
	msg.Header.SessionID = "undefined-session-id"
	sockMock.RecvChan <- msg

	select {
	case <-sockMock.closed:
		t.Error("the session was not expected to close")
		t.Fail()
	case <-time.After(time.Second):
		msg.Header.SessionID = "c4993deb-26b4-4c58-aaee-fd0c9e694328"
		msg.Header.MsgType = wsshell.MessageTypeStopShell
		msg.Body = []byte{}
		sockMock.RecvChan <- msg
	}

	select {
	case <-sockMock.closed:

	case <-time.After(time.Second * 10):
		t.Error("timeout waiting for terminal to close")
		t.Fail()
	}

	t.Log("checking command execution results")
	found := false
	for i := 0; i < 8; i++ {
		t.Logf("checking if %s contains %s", testFileNameTemporary, testData)
		data, _ := os.ReadFile(testFileNameTemporary)
		trimmedData := strings.TrimRight(string(data), "\n")
		t.Logf("got: '%s'", trimmedData)
		if trimmedData == testData {
			found = true
			break
		}
		time.Sleep(time.Second)
	}
	assert.True(t, found, "file contents must match expected value")
}

func TestMenderShellStopByUserId(t *testing.T) {
	d, sockMock := newTestDaemon(t)

	in := sockMock.Input()
	out := sockMock.Output()

	in <- ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypeShell,
			MsgType:   wsshell.MessageTypeSpawnShell,
			SessionID: "c4993deb-26b4-4c58-aaee-fd0c9e694328",
			Properties: map[string]interface{}{
				propertyUserID: "user-id-unit-tests-a00908-f6723467-561234ff",
				"status":       wsshell.NormalMessage,
			},
		},
	}

	message := <-out
	assert.NotNil(t, message)
	t.Logf("read message: type=%s, session_id=%s, data=%s", message.Header.MsgType, message.Header.SessionID, message.Body)

	sessions := session.MenderShellSessionsGetByUserId("user-id-unit-tests-a00908-f6723467-561234ff")
	if assert.True(t, len(sessions) > 0) {
		assert.NotNil(t, sessions[0])
	}
	sessionsCount := d.shellsSpawned

	in <- ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypeShell,
			MsgType:   wsshell.MessageTypeStopShell,
			SessionID: "c4993deb-26b4-4c58-aaee-fd0c9e694328",
		},
	}

	for message = range out {
		t.Logf("read message: type=%s, session_id=%s, data=%s", message.Header.MsgType, message.Header.SessionID, message.Body)
		if message.Header.MsgType == wsshell.MessageTypeStopShell {
			break
		}
	}
	assert.NotNil(t, message)
	t.Logf("read message: type=%s, session_id=%s, data=%s", message.Header.MsgType, message.Header.SessionID, message.Body)

	time.Sleep(time.Second * 5)
	assert.Equal(t, sessionsCount-1, d.shellsSpawned)
}

func TestMenderShellUnknownMessage(t *testing.T) {
	_, sockMock := newTestDaemon(t)

	sockMock.Input() <- ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypeShell,
			MsgType:   "undefined",
			SessionID: "c4993deb-26b4-4c58-aaee-fd0c9e694328",
		},
	}
	select {
	case msg := <-sockMock.Output():
		assert.NotNil(t, msg)
		t.Logf("read: proto=%d, type=%s, session_id=%s, data=%s", msg.Header.Proto, msg.Header.MsgType, msg.Header.SessionID, msg.Body)
		assert.Contains(t, string(msg.Body), "unknown message protocol and type: 1/undefined")
	case <-time.After(time.Second * 10):
		t.Logf("timeout waiting for output")
		t.FailNow()
	}
}

// maxUserSessions controls how many sessions user can have.
func TestMenderShellSessionLimitPerUser(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Errorf("cant get current user: %s", err.Error())
		t.FailNow()
	}
	_, sockMock := newTestDaemonWithConfig(t, &config.MenderShellConfig{
		MenderShellConfigFromFile: config.MenderShellConfigFromFile{
			ShellCommand: "/bin/sh",
			User:         currentUser.Username,
			Terminal: config.TerminalConfig{
				Width:  24,
				Height: 80,
			},
			Sessions: config.SessionsConfig{
				StopExpired:     true,
				ExpireAfter:     128,
				ExpireAfterIdle: 32,
				MaxPerUser:      2,
			},
		},
	})

	var i int
	in := sockMock.Input()
	out := sockMock.Output()
	timeout := time.After(time.Second * 10)
	for i = 0; i < session.MaxUserSessions; i++ {
		sessID := strconv.Itoa(i)
		in <- ws.ProtoMsg{
			Header: ws.ProtoHdr{
				Proto:     ws.ProtoTypeShell,
				MsgType:   wsshell.MessageTypeSpawnShell,
				SessionID: sessID,
				Properties: map[string]interface{}{
					propertyUserID:         "user",
					propertyTerminalWidth:  int64(80),
					propertyTerminalHeight: int64(60),
					"status":               wsshell.NormalMessage,
				},
			},
		}
	ResponseLoop:
		for {
			select {
			case msg := <-out:
				if msg.Header.MsgType == wsshell.MessageTypeSpawnShell &&
					msg.Header.SessionID == sessID {
					break ResponseLoop
				}
			case <-timeout:
				t.Error("timeout waiting for spawn shell response")
				t.FailNow()
			}
		}
	}
	sessID := strconv.Itoa(i)
	in <- ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypeShell,
			MsgType:   wsshell.MessageTypeSpawnShell,
			SessionID: sessID,
			Properties: map[string]interface{}{
				propertyUserID:         "user",
				propertyTerminalWidth:  int64(80),
				propertyTerminalHeight: int64(60),
				"status":               wsshell.NormalMessage,
			},
		},
	}
	var done bool
	for !done {
		select {
		case msg := <-out:
			if msg.Header.MsgType == wsshell.MessageTypeSpawnShell &&
				msg.Header.SessionID == sessID {
				t.Logf("read: proto=%d, type=%s, session_id=%s, data=%s",
					msg.Header.Proto, msg.Header.MsgType, msg.Header.SessionID, msg.Body)
				if assert.Contains(t, msg.Header.Properties, "status") {
					assert.Equal(t, wsshell.ErrorMessage, msg.Header.Properties["status"])
					assert.Equal(t, "user has too many open sessions", string(msg.Body))
				}
				done = true
			}
		case <-timeout:
			done = true
			t.Error("timeout waiting for spawn shell response")
			t.FailNow()
		}
	}
}

func TestMenderShellStopDaemon(t *testing.T) {
	d, sockMock := newTestDaemon(t)
	d.StopDaemon()
	timeout := time.After(time.Second * 5)
	select {
	case <-d.done:
	case <-timeout:
		t.Errorf("timeout waiting for daemon to shutdown")
		t.Fail()
	}
	select {
	case <-sockMock.closed:
	case <-timeout:
		t.Errorf("timeout waiting for daemon to shutdown")
		t.Fail()
	}
}

func TestMenderShellMaxShellsLimit(t *testing.T) {
	// NOTE: This test is stateful and must be run serially
	maxUserSessions := session.MaxUserSessions
	maxShells := config.MaxShellsSpawned

	session.MaxUserSessions = 4
	config.MaxShellsSpawned = 2
	defer func() {
		session.MaxUserSessions = maxUserSessions
		config.MaxShellsSpawned = maxShells
	}()

	d, sockMock := newTestDaemon(t)

	var i int
	for i = 0; i < int(config.MaxShellsSpawned); i++ {
		err := d.routeMessage(&ws.ProtoMsg{
			Header: ws.ProtoHdr{
				Proto:     ws.ProtoTypeShell,
				MsgType:   wsshell.MessageTypeSpawnShell,
				SessionID: uuid.NewV4().String(),
				Properties: map[string]interface{}{
					propertyUserID:         "user",
					propertyTerminalWidth:  int64(80),
					propertyTerminalHeight: int64(60),
					"status":               wsshell.NormalMessage,
				},
			},
		}, sockMock)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
	}

	sessID := strconv.Itoa(i)
	err := d.routeMessage(&ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypeShell,
			MsgType:   wsshell.MessageTypeSpawnShell,
			SessionID: sessID,
			Properties: map[string]interface{}{
				propertyUserID:         "user",
				propertyTerminalWidth:  int64(80),
				propertyTerminalHeight: int64(60),
				"status":               wsshell.NormalMessage,
			},
		},
	}, sockMock)
	assert.Error(t, err)
}

func TestOutputStatus(t *testing.T) {
	d := &Daemon{}
	stdLog := logrus.StandardLogger()
	var buf bytes.Buffer
	out := stdLog.Out
	stdLog.Out = &buf
	defer func() { stdLog.Out = out }()
	d.outputStatus()
	assert.Contains(t, buf.String(), "nt-connect daemon v")
}

func TestMessageMainLoop(t *testing.T) {
	t.Log("starting mock httpd with websockets")

	newSock := &SocketMock{
		SendChan: make(chan ws.ProtoMsg, 1),
		RecvChan: make(chan ws.ProtoMsg),
		ErrChan:  make(chan error),
		closed:   make(chan struct{}),
	}
	d, sockMock := newTestDaemon(t)
	mockClient := d.apiClient.(*Client)
	timeout := time.After(time.Second * 10)

	t.Run("error chan", func(t *testing.T) {
		select {
		case sockMock.ErrChan <- errors.New("internal error"):
		case <-timeout:
			t.Error("timeout waiting for messageloop to receive error")
			t.FailNow()
		}
	})

	t.Run("reconnect on closed socket", func(t *testing.T) {
		mockClient.On("OpenSocket",
			mock.MatchedBy(func(context.Context) bool { return true }),
			mock.MatchedBy(func(*api.Authz) bool { return true })).
			Return(newSock, nil).
			Once()

		close(sockMock.RecvChan)
		select {
		case newSock.Input() <- ws.ProtoMsg{}:
		case <-timeout:
			t.Error("timeout waiting for messageloop to reconnect")
			t.FailNow()
		}
	})
	t.Run("internal error reconnecting", func(t *testing.T) {
		mockClient.On("OpenSocket",
			mock.MatchedBy(func(context.Context) bool { return true }),
			mock.MatchedBy(func(*api.Authz) bool { return true })).
			Return(nil, errors.New("internal error")).
			Once()
		newSock.Close()
		close(newSock.RecvChan)
		select {
		case <-d.done:
		case <-timeout:
			t.Error("timeout waiting for messageloop to shut down")
			t.FailNow()
		}
	})

}

func TestRouteMessage(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		Name string

		Router  *sessmocks.Router
		Message ws.ProtoMsg

		Error error
	}{{
		Name: "ok, session router",

		Router: func() *sessmocks.Router {
			router := new(sessmocks.Router)
			router.On("RouteMessage", &ws.ProtoMsg{
				Header: ws.ProtoHdr{
					Proto:   ws.ProtoType(123),
					MsgType: "foobar",
				},
			}, mock.MatchedBy(func(api.Sender) bool { return true })).
				Return(nil)
			return router
		}(),
		Message: ws.ProtoMsg{
			Header: ws.ProtoHdr{
				Proto:   ws.ProtoType(123),
				MsgType: "foobar",
			},
		},
	}, {
		Name: "error, session router",

		Router: func() *sessmocks.Router {
			router := new(sessmocks.Router)
			router.On("RouteMessage", &ws.ProtoMsg{
				Header: ws.ProtoHdr{
					Proto:   ws.ProtoType(123),
					MsgType: "foobar",
				},
			}, mock.MatchedBy(func(api.Sender) bool { return true })).
				Return(errors.New("bad!"))
			return router
		}(),
		Message: ws.ProtoMsg{
			Header: ws.ProtoHdr{
				Proto:   ws.ProtoType(123),
				MsgType: "foobar",
			},
		},
		Error: errors.New("bad!"),
	}}
	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			defer tc.Router.AssertExpectations(t)

			daemon := &Daemon{
				FileTransferConfig: config.FileTransferConfig{
					Disable: false,
				},
			}
			sockMock := &SocketMock{
				SendChan: make(chan ws.ProtoMsg, 1),
			}
			daemon.router = tc.Router
			err := daemon.routeMessage(&tc.Message, sockMock)

			if tc.Error != nil {
				assert.EqualError(t, err, tc.Error.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDecreaseSpawnedShellsCount(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		Name string

		CurrentCount  uint
		DecreaseBy    uint
		ExpectedCount uint
	}{
		{
			Name: "decrease by 1 with 1",

			CurrentCount: 1,
			DecreaseBy:   1,
		},
		{
			Name: "decrease by 1 with many",

			CurrentCount:  3,
			DecreaseBy:    1,
			ExpectedCount: 2,
		},
		{
			Name: "decrease by many with many",

			CurrentCount: 3,
			DecreaseBy:   3,
		},
		{
			Name: "decrease by many with some",

			CurrentCount:  255,
			DecreaseBy:    3,
			ExpectedCount: 252,
		},
		{
			Name: "decrease by some with many",

			CurrentCount:  3,
			DecreaseBy:    255,
			ExpectedCount: 0,
		},
		{
			Name: "decrease by many with 0",

			DecreaseBy: 3,
		},
		{
			Name: "decrease by 0 with 0",
		},
	}
	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			daemon := &Daemon{
				FileTransferConfig: config.FileTransferConfig{
					Disable: false,
				},
			}

			daemon.shellsSpawned = tc.CurrentCount
			daemon.DecreaseSpawnedShellsCount(tc.DecreaseBy)

			assert.Equal(t, tc.ExpectedCount, daemon.shellsSpawned)
		})
	}
}
