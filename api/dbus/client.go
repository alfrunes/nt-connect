// Copyright 2021 Northern.tech AS
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

package dbus

import (
	"context"
	"fmt"
	"time"

	"github.com/northerntechhq/nt-connect/api"
	"github.com/northerntechhq/nt-connect/api/ws"
	"github.com/northerntechhq/nt-connect/client/dbus"
)

// DbBus constants for the Mender Authentication Manager
const (
	DBusObjectName                    = "io.mender.AuthenticationManager"
	DBusObjectPath                    = "/io/mender/AuthenticationManager"
	DBusInterfaceName                 = "io.mender.Authentication1"
	DBusMethodNameGetJwtToken         = "GetJwtToken"
	DBusMethodNameFetchJwtToken       = "FetchJwtToken"
	DBusSignalNameJwtTokenStateChange = "JwtTokenStateChange"
	DBusMethodTimeoutInMilliSeconds   = 5000
)

const timeout = 10 * time.Second

// ClientDBus is the implementation of the client for the Mender
// Authentication Manager which communicates using DBUS
type ClientDBus struct {
	dbusAPI          dbus.DBusAPI
	dbusConnection   dbus.Handle
	authManagerProxy dbus.Handle
}

var _ api.Client = &ClientDBus{}

// NewAuthClient returns a new api.Client
func NewClient(dbusAPI dbus.DBusAPI, objectName, objectPath, interfaceName string) (*ClientDBus, error) {
	if dbusAPI == nil {
		var err error
		dbusAPI, err = dbus.GetDBusAPI()
		if err != nil {
			return nil, err
		}
	}
	dbusConnection, err := dbusAPI.BusGet(dbus.GBusTypeSystem)
	if err != nil {
		return nil, err
	}
	authManagerProxy, err := dbusAPI.BusProxyNew(
		dbusConnection,
		objectName,
		objectPath,
		interfaceName,
	)
	if err != nil {
		return nil, err
	}
	return &ClientDBus{
		dbusAPI:          dbusAPI,
		dbusConnection:   dbusConnection,
		authManagerProxy: authManagerProxy,
	}, nil
}

// GetJWTToken returns a device JWT token and server URL
func (a *ClientDBus) Authenticate(ctx context.Context) (*api.Authz, error) {
	response, err := a.dbusAPI.BusProxyCall(
		a.authManagerProxy,
		DBusMethodNameGetJwtToken,
		nil,
		DBusMethodTimeoutInMilliSeconds,
	)
	if err != nil {
		return nil, err
	}
	token, serverURL := response.GetTwoStrings()
	return &api.Authz{
		Token:     token,
		ServerURL: serverURL,
	}, nil
}

func (a *ClientDBus) OpenSocket(ctx context.Context, authz *api.Authz) (api.Socket, error) {
	return ws.Connect(ctx, authz)
}

// FetchJWTToken schedules the fetching of a new device JWT token
//
//nolint:unused
func (a *ClientDBus) FetchJWTToken() (bool, error) {
	response, err := a.dbusAPI.BusProxyCall(
		a.authManagerProxy,
		DBusMethodNameFetchJwtToken,
		nil,
		DBusMethodTimeoutInMilliSeconds,
	)
	if err != nil {
		return false, err
	}
	return response.GetBoolean(), nil
}

// WaitForJwtTokenStateChange synchronously waits for the JwtTokenStateChange signal
func (a *ClientDBus) WaitForAuthStateChange() (*api.Authz, error) {
	signals, err := a.dbusAPI.WaitForSignal(DBusSignalNameJwtTokenStateChange, timeout)
	if err != nil {
		return nil, err
	}
	if len(signals) > 1 {
		if signals[0].ParamType == dbus.GDBusTypeString &&
			signals[1].ParamType == dbus.GDBusTypeString {
			return &api.Authz{
				Token:     signals[0].ParamData.(string),
				ServerURL: signals[1].ParamData.(string),
			}, nil
		} else {
			return nil, fmt.Errorf("unexpected response type (%s, %s) from DBus API", signals[0].ParamType, signals[1].ParamType)
		}
	}
	return nil, fmt.Errorf(
		"insufficient number of parameters (%d) received from dbus API",
		len(signals),
	)
}
