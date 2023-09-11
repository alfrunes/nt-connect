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
package shell

import (
	"errors"
	"fmt"
	"io"

	"os/exec"
	"testing"
	"time"

	"github.com/creack/pty"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"

	"github.com/mendersoftware/go-lib-micro/ws"
)

var messages []string

func TestNewMenderShell(t *testing.T) {
	s := NewShell(nil, "", nil, nil)
	assert.NotNil(t, s)
}

type chanSock struct {
	send  chan ws.ProtoMsg
	close chan struct{}
}

func (sock chanSock) Send(msg ws.ProtoMsg) error {
	select {
	case sock.send <- msg:
	case <-sock.close:
		return errors.New("closed")
	}
	return nil
}

func TestNewMenderShellReadStdIn(t *testing.T) {
	messages = []string{}
	cmd := exec.Command("/bin/sh")
	if cmd == nil {
		t.Fatal("cant execute shell")
	}
	cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", "xterm-256color"))

	pseudoTTY, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		t.Fatal("cant execute shell")
	}

	cs := chanSock{
		send:  make(chan ws.ProtoMsg, 1),
		close: make(chan struct{}),
	}
	defer close(cs.close)
	s := NewShell(cs, uuid.NewV4().String(), pseudoTTY, pseudoTTY)
	assert.NotNil(t, s)

	s.Start()
	assert.True(t, s.IsRunning())

	message := "_ok_"
	pseudoTTY.Write([]byte("echo " + message + "\n"))
	select {
	case msg := <-cs.send:
		assert.Contains(t, string(msg.Body), message)
	case <-time.After(time.Second * 10):
		t.Error("timeout waiting for tty output")
		t.FailNow()
	}

	s.Stop()
	assert.False(t, s.IsRunning())
}

type devNull struct{}

func (devNull) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (devNull) Write(b []byte) (int, error) {
	return len(b), nil
}

func TestPipeStdout(t *testing.T) {
	sock := chanSock{
		send:  make(chan ws.ProtoMsg),
		close: make(chan struct{}),
	}
	close(sock.close)
	shell := &Shell{
		sock:      sock,
		sessionId: "unit-tests-sessions-id",
		r:         devNull{},
		w:         devNull{},
		running:   false,
	}

	rc := shell.IsRunning()
	assert.False(t, rc)

	shell.Start()
	rc = shell.IsRunning()
	assert.True(t, rc)

	shell.Stop()
	rc = shell.IsRunning()
	assert.False(t, rc)

	shell.Start()
	rc = shell.IsRunning()
	assert.True(t, rc)

	shell.running = false
	rc = shell.IsRunning()
	assert.False(t, rc)
}
