// Copyright 2022 Northern.tech AS
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
	"context"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/mendersoftware/go-lib-micro/ws"
	wsshell "github.com/mendersoftware/go-lib-micro/ws/shell"

	"github.com/northerntechhq/nt-connect/api"
	apidbus "github.com/northerntechhq/nt-connect/api/dbus"
	apihttp "github.com/northerntechhq/nt-connect/api/http"
	"github.com/northerntechhq/nt-connect/client/dbus"
	"github.com/northerntechhq/nt-connect/config"
	"github.com/northerntechhq/nt-connect/limits/filetransfer"
	"github.com/northerntechhq/nt-connect/session"
)

type Daemon struct {
	spawnedShellsMutex      sync.Mutex
	done                    chan struct{}
	signal                  chan os.Signal
	authorized              bool
	username                string
	shell                   string
	shellArguments          []string
	deviceConnectUrl        string
	sessionSweepTicker      <-chan time.Time
	expireSessionsAfter     time.Duration
	expireSessionsAfterIdle time.Duration
	terminalString          string
	uid                     uint64
	gid                     uint64
	homeDir                 string
	shellsSpawned           uint
	debug                   bool
	trace                   bool
	router                  session.Router
	config.APIConfig
	config.TerminalConfig
	config.FileTransferConfig
	config.PortForwardConfig
	config.MenderClientConfig
	Chroot string
}

func NewDaemon(conf *config.MenderShellConfig) *Daemon {
	// Setup ProtoMsg routes.
	routes := make(session.ProtoRoutes)
	if !conf.Terminal.Disable {
		// Shell message is not handled by the Session, but the map
		// entry must be set to give the correct 'accept' response.
		routes[ws.ProtoTypeShell] = nil
	}
	if !conf.FileTransfer.Disable {
		routes[ws.ProtoTypeFileTransfer] = session.FileTransfer(conf.Limits)
	}
	if !conf.PortForward.Disable {
		routes[ws.ProtoTypePortForward] = session.PortForward()
	}
	if !conf.MenderClient.Disable {
		routes[ws.ProtoTypeMenderClient] = session.MenderClient()
	}
	router := session.NewRouter(
		routes, session.Config{
			IdleTimeout: time.Second * 10,
		},
	)

	daemon := Daemon{
		done:                    make(chan struct{}),
		authorized:              false,
		username:                conf.User,
		shell:                   conf.ShellCommand,
		shellArguments:          conf.ShellArguments,
		expireSessionsAfter:     time.Second * time.Duration(conf.Sessions.ExpireAfter),
		expireSessionsAfterIdle: time.Second * time.Duration(conf.Sessions.ExpireAfterIdle),
		deviceConnectUrl:        config.DefaultDeviceConnectPath,
		terminalString:          config.DefaultTerminalString,
		TerminalConfig:          conf.Terminal,
		FileTransferConfig:      conf.FileTransfer,
		PortForwardConfig:       conf.PortForward,
		MenderClientConfig:      conf.MenderClient,
		APIConfig:               conf.APIConfig,
		Chroot:                  conf.Chroot,
		shellsSpawned:           0,
		debug:                   conf.Debug,
		trace:                   conf.Trace,
		router:                  router,
	}
	sweepPeriod := daemon.expireSessionsAfter
	if 0 > daemon.expireSessionsAfterIdle && sweepPeriod > daemon.expireSessionsAfterIdle {
		sweepPeriod = daemon.expireSessionsAfterIdle
	}
	if sweepPeriod > 0 {
		ticker := time.NewTicker(sweepPeriod)
		daemon.sessionSweepTicker = ticker.C
	} else {
		daemon.sessionSweepTicker = make(chan time.Time)
	}

	return &daemon
}

func (d *Daemon) StopDaemon() {
	select {
	case <-d.done:
	default:
		close(d.done)
	}
}

func (d *Daemon) outputStatus() {
	log.Infof("nt-connect daemon v%s", config.VersionString())
	log.Info(" status: ")
	d.spawnedShellsMutex.Lock()
	log.Infof("  shells: %d/%d", d.shellsSpawned, config.MaxShellsSpawned)
	d.spawnedShellsMutex.Unlock()
	log.Infof("  sessions: %d", session.MenderShellSessionGetCount())
	sessionIds := session.MenderShellSessionGetSessionIds()
	for _, id := range sessionIds {
		s := session.MenderShellSessionGetById(id)
		log.Infof("   id:%s status:%d started:%s", id, s.GetStatus(), s.GetStartedAtFmt())
		log.Infof("   expires:%s active:%s", s.GetExpiresAtFmt(), s.GetActiveAtFmt())
		log.Infof("   shell:%s", s.GetShellCommandPath())
	}
	log.Info("  file-transfer:")
	tx, rx, tx1m, rx1m := filetransfer.GetCounters()
	log.Infof("   total: tx/rx %d/%d", tx, rx)
	log.Infof("   1m: tx rx %.2f %.2f (w)", tx1m, rx1m)
}

func (d *Daemon) handleSignal(sig os.Signal) error {
	sig.Signal()
	switch sig {
	case unix.SIGINT, unix.SIGTERM:
		return fmt.Errorf("terminated by signal: %s", sig)
	case unix.SIGUSR1:
		d.outputStatus()
	}
	return nil
}

func (d *Daemon) connect(ctx context.Context, client api.Client, authz *api.Authz) (api.Socket, *api.Authz, error) {
	var (
		sock           api.Socket
		err            error
		i              int
		logReauthorize func()
	)
	if bc, ok := client.(api.BackoffClient); ok {
		logReauthorize = func() {
			i++
			const durationResolution = time.Millisecond * 10
			nextAttempt, attempt := bc.NextAttempt()
			until := time.Until(nextAttempt).
				Round(durationResolution)
			var durationStr string
			if until < 0 {
				durationStr = "now"
			} else {
				durationStr = until.String()
			}
			log.Infof("attempting to reauthorize %s: attempt %d", durationStr, attempt)
		}
	} else {
		logReauthorize = func() {
			i++
			log.Infof("attempting to reauthorize: attempt %d", i)
		}
	}
	for {
		if !authz.IsZero() {
			sock, err = client.OpenSocket(ctx, authz)
		} else {
			err = api.ErrUnauthorized
		}
		if errors.Is(err, api.ErrUnauthorized) {
			log.Infof("client not authorized: sending authorization request")
			for {
				authz, err = client.Authenticate(ctx)
				if err != nil {
					log.Infof("authorization request failed: %s", err.Error())
					if errors.Is(err, api.ErrUnauthorized) {
						logReauthorize()
						continue
					}
					return nil, nil, err
				} else {
					break
				}
			}
			continue
		}
		if err != nil {
			log.Errorf("failed to establish socket connection: %s", err.Error())
			continue
		}
		break
	}
	log.Infof("connection established with %q", authz.ServerURL)
	return sock, authz, err
}

func (d *Daemon) mainLoop(client api.Client) (err error) {
	log.Trace("mainLoop: starting")
	d.signal = make(chan os.Signal, 1)
	signal.Notify(d.signal, syscall.SIGTERM)
	signal.Notify(d.signal, syscall.SIGINT)
	signal.Notify(d.signal, syscall.SIGUSR1)
	defer signal.Stop(d.signal)

	ctx := context.Background()
	go func() {
		err = d.messageLoop(ctx, client)
		d.StopDaemon()
	}()
	for {
		select {
		case <-d.done:
			log.Trace("mainLoop: returning")
			return err
		case sig := <-d.signal:
			if err := d.handleSignal(sig); err != nil {
				return err
			}
		case <-d.sessionSweepTicker:
			d.handleExpiredSessions()
		}
	}
}

func (d *Daemon) messageLoop(ctx context.Context, client api.Client) (err error) {
	log.Trace("messageLoop: starting")
	var (
		sock  api.Socket
		authz *api.Authz
	)
	sock, authz, err = d.connect(ctx, client, nil)
	if err != nil {
		return err
	}
	msgChan := sock.ReceiveChan()
	errChan := sock.ErrorChan()
	defer sock.Close()
	for {
		select {
		case <-d.done:
			return nil
		case err := <-errChan:
			log.Errorf("received error from ingest channel: %s", err.Error())
		case msg, open := <-msgChan:
			if open {
				log.Tracef("got message: type:%s data length:%d", msg.Header.MsgType, len(msg.Body))
				err = d.routeMessage(&msg, sock)
				if err != nil {
					log.Warnf("error routing message: %s", err.Error())
				}
			} else {
				select {
				case err = <-errChan:
					err = fmt.Errorf("socket closed with error: %w", err)
				default:
					err = errors.New("socket closed")
				}
				_ = sock.Close()
				sock, authz, err = d.connect(ctx, client, authz)
				if err != nil {
					return err
				}
				msgChan, errChan = sock.ReceiveChan(), sock.ErrorChan()
			}
		}
	}
}

func (d *Daemon) setupLogging() {
	if d.trace {
		log.SetLevel(log.TraceLevel)
	} else if d.debug {
		log.SetLevel(log.DebugLevel)
	}
}

func (d *Daemon) DecreaseSpawnedShellsCount(shellStoppedCount uint) {
	d.spawnedShellsMutex.Lock()
	defer d.spawnedShellsMutex.Unlock()
	if d.shellsSpawned == 0 {
		log.Warn("can't decrement shellsSpawned count: it is 0.")
	} else {
		if shellStoppedCount >= d.shellsSpawned {
			d.shellsSpawned = 0
		} else {
			d.shellsSpawned -= shellStoppedCount
		}
	}
}

func (d *Daemon) handleExpiredSessions() {
	shellStoppedCount, sessionStoppedCount, totalExpiredLeft, err :=
		session.MenderSessionTerminateExpired()
	if err != nil {
		log.Errorf("main-loop: failed to terminate some expired sessions, left: %d",
			totalExpiredLeft)
	} else if sessionStoppedCount > 0 {
		d.DecreaseSpawnedShellsCount(uint(sessionStoppedCount))
		log.Infof("main-loop: stopped %d sessions, %d shells, expired sessions left: %d",
			shellStoppedCount, sessionStoppedCount, totalExpiredLeft)
	}
}

// starts all needed elements of the mender-connect daemon
//   - executes given shell (shell.ExecuteShell)
//   - get dbus API and starts the dbus main loop (dbus.GetDBusAPI(), go dbusAPI.MainLoopRun(loop))
//   - creates a new dbus client and connects to dbus (mender.NewAuthClient(dbusAPI),
//     client.Connect(...))
//   - gets the JWT token from the mender-client via dbus (client.GetJWTToken())
//   - connects to the backend and returns a new websocket (deviceconnect.Connect(...))
//   - starts the message flow between the shell and websocket (shell.NewMenderShell(...))
func (d *Daemon) Run() error {
	d.setupLogging()
	log.Trace("daemon Run starting")
	u, err := user.Lookup(d.username)
	if err == nil && u == nil {
		return errors.New("unknown error while getting a user id")
	}
	if err != nil {
		return err
	}

	d.homeDir = u.HomeDir

	d.uid, err = strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return err
	}

	d.gid, err = strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return err
	}

	log.Trace("mender-connect connecting to dbus")

	var client api.Client
	switch d.APIConfig.APIType {
	case config.APITypeHTTP:
		client, err = apihttp.NewClient(d.APIConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize auth client: %w", err)
		}
	case config.APITypeDBus:
		dbusAPI, err := dbus.GetDBusAPI()
		if err != nil {
			return err
		}

		//new dbus client
		client, err = apidbus.NewClient(
			dbusAPI,
			apidbus.DBusObjectName,
			apidbus.DBusObjectPath,
			apidbus.DBusInterfaceName,
		)
		if err != nil {
			log.Errorf("mender-connect dbus failed to create client, error: %s", err.Error())
			return err
		}

		//dbus main loop, required.
		loop := dbusAPI.MainLoopNew()
		go dbusAPI.MainLoopRun(loop)
		defer dbusAPI.MainLoopQuit(loop)
	default:
		return fmt.Errorf("invalid API config: unknown type %q", d.APIConfig.APIType)
	}

	if d.Chroot != "" {
		err := syscall.Chroot(d.Chroot)
		if err != nil {
			return err
		}
	}

	log.Trace("mender-connect entering main loop.")
	err = d.mainLoop(client)
	if err != nil {
		log.Errorf("mainLoop terminating after error: %s", err)
	} else {
		log.Trace("mainLoop: returning")
	}
	return nil
}

func (d *Daemon) routeMessage(msg *ws.ProtoMsg, sock api.Socket) error {
	var err error
	// NOTE: the switch is required for backward compatibility, otherwise
	//       routing is performed and managed by the session.Router.
	//       Use the new API in sessions package (see filetransfer.go for an example)
	switch msg.Header.Proto {
	case ws.ProtoTypeShell:
		if d.TerminalConfig.Disable {
			break
		}
		switch msg.Header.MsgType {
		case wsshell.MessageTypeSpawnShell:
			return d.routeMessageSpawnShell(msg, sock)
		case wsshell.MessageTypeStopShell:
			return d.routeMessageStopShell(msg, sock)
		case wsshell.MessageTypeShellCommand:
			return d.routeMessageShellCommand(msg, sock)
		case wsshell.MessageTypeResizeShell:
			return d.routeMessageShellResize(msg, sock)
		case wsshell.MessageTypePongShell:
			return d.routeMessagePongShell(msg, sock)
		}
	default:
		return d.router.RouteMessage(msg, sock)
	}
	err = errors.New(
		fmt.Sprintf(
			"unknown message protocol and type: %d/%s",
			msg.Header.Proto,
			msg.Header.MsgType,
		),
	)
	response := ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     msg.Header.Proto,
			MsgType:   msg.Header.MsgType,
			SessionID: msg.Header.SessionID,
			Properties: map[string]interface{}{
				"status": wsshell.ErrorMessage,
			},
		},
		Body: []byte(err.Error()),
	}
	if err := sock.Send(response); err != nil {
		log.Errorf(errors.Wrap(err, "unable to send the response message").Error())
	}
	return err
}

func (d *Daemon) routeMessageResponse(response *ws.ProtoMsg, err error, sock api.Sender) {
	if err != nil {
		log.Errorf(err.Error())
		response.Header.Properties["status"] = wsshell.ErrorMessage
		response.Body = []byte(err.Error())
	} else if response == nil {
		return
	}
	if err := sock.Send(*response); err != nil {
		log.Errorf(errors.Wrap(err, "unable to send the response message").Error())
	}
}
