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

package dbus

import (
	"context"
	"fmt"

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

// ClientDBus is the implementation of the client for the Mender
// Authentication Manager which communicates using DBUS
type ClientDBus struct {
	dbusAPI          dbus.DBusAPI
	dbusConnection   dbus.Handle
	authManagerProxy dbus.Handle
	wsClient         *ws.Client
}

var _ api.Client = &ClientDBus{}

// NewAuthClient returns a new api.Client
func NewClient(
	dbusAPI dbus.DBusAPI,
	objectName, objectPath, interfaceName string,
) (*ClientDBus, error) {
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
		wsClient:         ws.NewClient(nil),
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
		return a.waitForAuthStateChange(ctx)

	}
	token, serverURL := response.GetTwoStrings()
	return &api.Authz{
		Token:     token,
		ServerURL: serverURL,
	}, nil
}

func (a *ClientDBus) OpenSocket(ctx context.Context, authz *api.Authz) (api.Socket, error) {
	return a.wsClient.OpenSocket(ctx, authz)
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
func (a *ClientDBus) waitForAuthStateChange(ctx context.Context) (authz *api.Authz, err error) {
	c := a.dbusAPI.GetChannelForSignal(DBusSignalNameJwtTokenStateChange)
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case signals := <-c:
		if len(signals) > 1 {
			if signals[0].ParamType == dbus.GDBusTypeString &&
				signals[1].ParamType == dbus.GDBusTypeString {
				authz = &api.Authz{
					Token:     signals[0].ParamData.(string),
					ServerURL: signals[1].ParamData.(string),
				}
			} else {
				err = fmt.Errorf(
					"unexpected response type (%s, %s) from DBus API",
					signals[0].ParamType, signals[1].ParamType,
				)
			}
		} else {
			err = fmt.Errorf(
				"insufficient number of parameters (%d) received from dbus API",
				len(signals),
			)
		}
	}
	return authz, err
}

func (a *ClientDBus) SendInventory(_ context.Context, _ *api.Authz, _ api.Inventory) error {
	// Inventory is assumed managed by the mender client.
	// This function exists simply for interface completion.
	return nil
}
