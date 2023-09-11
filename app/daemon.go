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
	"crypto/tls"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
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
	shellCommand            string
	shellArguments          []string
	deviceConnectUrl        string
	sessionSweepTicker      <-chan time.Time
	inventoryTicker         <-chan time.Time
	inventoryDigest         []byte
	inventoryExecutable     string
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
	apiClient               api.Client
	config.TerminalConfig
	config.FileTransferConfig
	config.PortForwardConfig
	config.MenderClientConfig
	Chroot string
}

func newDaemon(conf *config.NTConnectConfig) *Daemon {
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

	daemon := &Daemon{
		done:                    make(chan struct{}),
		authorized:              false,
		username:                conf.User,
		shellCommand:            conf.ShellCommand,
		shellArguments:          conf.ShellArguments,
		expireSessionsAfter:     time.Second * time.Duration(conf.Sessions.ExpireAfter),
		expireSessionsAfterIdle: time.Second * time.Duration(conf.Sessions.ExpireAfterIdle),
		inventoryExecutable:     conf.APIConfig.InventoryExecutable,
		deviceConnectUrl:        config.DefaultDeviceConnectPath,
		terminalString:          config.DefaultTerminalString,
		TerminalConfig:          conf.Terminal,
		FileTransferConfig:      conf.FileTransfer,
		PortForwardConfig:       conf.PortForward,
		MenderClientConfig:      conf.MenderClient,
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
	return daemon
}

func NewDaemon(conf *config.NTConnectConfig) (*Daemon, error) {
	daemon := newDaemon(conf)

	if conf.Chroot != "" {
		var (
			chrootExec string
			chrootPath string
		)
		chrootPath, err := filepath.EvalSymlinks(conf.Chroot)
		for _, chrootExec = range []string{"/sbin/chroot", "/bin/chroot"} {
			_, err = os.Stat(chrootExec)
			if err == nil {
				chrootExec, err = filepath.EvalSymlinks(chrootExec)
				break
			}
		}
		if err != nil {
			return nil, fmt.Errorf(
				"failed to resolve chroot executable: %w", err,
			)
		}
		shellCommand := daemon.shellCommand
		daemon.shellCommand = chrootExec
		daemon.shellArguments = append(
			[]string{chrootPath,
				shellCommand},
			daemon.shellArguments...)
		log.Infof("running %q in chroot context %q",
			shellCommand, conf.Chroot)
	}

	var err error
	switch conf.APIConfig.APIType {
	case config.APITypeHTTP:
		var tlsConfig *tls.Config
		tlsConfig, err = conf.TLS.ToStdConfig()
		if err != nil {
			return nil, err
		}
		daemon.apiClient, err = apihttp.NewClient(conf.APIConfig, tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize auth client: %w", err)
		}
		daemon.inventoryTicker = time.NewTicker(
			time.Duration(conf.APIConfig.InventoryInterval),
		).C
	case config.APITypeDBus:
		dbusAPI, err := dbus.GetDBusAPI()
		if err != nil {
			return nil, err
		}

		//new dbus client
		daemon.apiClient, err = apidbus.NewClient(
			dbusAPI,
			apidbus.DBusObjectName,
			apidbus.DBusObjectPath,
			apidbus.DBusInterfaceName,
		)
		if err != nil {
			log.Errorf("nt-connect dbus failed to create client, error: %s", err.Error())
			return nil, err
		}

		//dbus main loop, requiredaemon.
		loop := dbusAPI.MainLoopNew()
		go dbusAPI.MainLoopRun(loop)
		go func() {
			<-daemon.done
			dbusAPI.MainLoopQuit(loop)
		}()
	default:
		return nil, fmt.Errorf("invalid API config: unknown type %q", conf.APIConfig.APIType)
	}

	daemon.apiClient = api.ExpBackoff(daemon.apiClient)

	return daemon, nil
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
	log.Infof("  sessions: %d", session.GetSessionCount())
	sessionIds := session.GetSessionIds()
	for _, id := range sessionIds {
		s := session.GetSessionById(id)
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

func (d *Daemon) connect(ctx context.Context, authz *api.Authz) (api.Socket, *api.Authz, error) {
	var (
		sock           api.Socket
		err            error
		i              int
		logReauthorize func()
	)
	if bc, ok := d.apiClient.(api.BackoffClient); ok {
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
		if authz.IsZero() || api.IsUnauthorized(err) {
			log.Infof("client not authorized: sending authorization request")
			for {
				authz, err = d.apiClient.Authenticate(ctx)
				if err != nil {
					log.Infof("authorization request failed: %s", err.Error())
					if api.IsRetryable(err) {
						logReauthorize()
						continue
					}
				} else {
					break
				}
			}
			continue
		} else {
			sock, err = d.apiClient.OpenSocket(ctx, authz)
		}
		if err != nil && !api.IsRetryable(err) {
			log.Errorf("failed to establish socket connection: %s", err.Error())
			return nil, nil, err
		}
		break
	}
	log.Infof("connection established with %q", authz.ServerURL)
	return sock, authz, err
}

func (d *Daemon) mainLoop() (err error) {
	log.Trace("mainLoop: starting")
	d.signal = make(chan os.Signal, 1)
	signal.Notify(d.signal, syscall.SIGTERM)
	signal.Notify(d.signal, syscall.SIGINT)
	signal.Notify(d.signal, syscall.SIGUSR1)
	defer signal.Stop(d.signal)

	ctx := context.Background()
	go func() {
		err = d.messageLoop(ctx)
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

type logFunc func(s string)

func (l logFunc) Write(b []byte) (int, error) {
	l(string(b))
	return len(b), nil
}

func (d *Daemon) dispatchInventory(ctx context.Context, authz *api.Authz) (err error) {
	log.Debug("running inventory script")
	cmd := exec.CommandContext(ctx, d.inventoryExecutable)
	var buf bytes.Buffer
	logger := func(s string) {
		log.Errorf("stderr: %s", s)
	}
	cmd.Stdout = &buf
	cmd.Stderr = logFunc(logger)

	err = cmd.Run()
	if err != nil {
		log.Errorf("error collecting inventory: %s", err.Error())
		return
	}
	inventory, err := api.NewInventoryFromStream(&buf)
	if err != nil {
		log.Errorf("failed to parse inventory data: %s", err)
		return
	}
	dgst := inventory.Digest()
	if bytes.Equal(d.inventoryDigest, dgst) {
		log.Debug("inventory did not change since last time")
	} else {
		err = d.apiClient.SendInventory(ctx, authz, inventory)
		if err != nil {
			log.Errorf("failed to submit inventory: %s", err.Error())
		} else {
			log.Debugf("inventory submitted: signature \"0x%x\"", dgst)
			d.inventoryDigest = dgst
		}
	}
	return err
}

func (d *Daemon) messageLoop(ctx context.Context) (err error) {
	log.Trace("messageLoop: starting")
	var (
		sock  api.Socket
		authz *api.Authz
		done  bool
	)
	sock, authz, err = d.connect(ctx, nil)
	if err != nil {
		return err
	}
	invCtx, cancel := context.WithCancel(ctx)
	go d.dispatchInventory(invCtx, authz) //nolint:errcheck
	msgChan := sock.ReceiveChan()
	errChan := sock.ErrorChan()
	defer sock.Close()
	for !done {
		select {
		case <-d.done:
			done = true

		case <-d.inventoryTicker:
			cancel()
			invCtx, cancel = context.WithCancel(ctx)
			go d.dispatchInventory(invCtx, authz) //nolint:errcheck

		case err = <-errChan:
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
				sock, authz, err = d.connect(ctx, authz)
				if err != nil {
					done = true
					continue
				}
				msgChan, errChan = sock.ReceiveChan(), sock.ErrorChan()
			}
		}
	}
	cancel()
	return err
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
		session.TerminateExpiredSessions()
	if err != nil {
		log.Errorf("main-loop: failed to terminate some expired sessions, left: %d",
			totalExpiredLeft)
	} else if sessionStoppedCount > 0 {
		d.DecreaseSpawnedShellsCount(uint(sessionStoppedCount))
		log.Infof("main-loop: stopped %d sessions, %d shells, expired sessions left: %d",
			shellStoppedCount, sessionStoppedCount, totalExpiredLeft)
	}
}

// starts the main loop and forks the go routine listening for incomming sessions
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

	log.Trace("nt-connect entering main loop.")
	err = d.mainLoop()
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
