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
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/northerntechhq/nt-connect/api"
	"github.com/northerntechhq/nt-connect/client/dbus"
	dbus_mocks "github.com/northerntechhq/nt-connect/client/dbus/mocks"
)

func TestNewClient(t *testing.T) {
	testCases := map[string]struct {
		busGet           dbus.Handle
		busGetError      error
		busProxyNew      dbus.Handle
		busProxyNewError error
	}{
		"ok": {
			busGet:      dbus.Handle(nil),
			busProxyNew: dbus.Handle(nil),
		},
		"error BusGet": {
			busGet:      dbus.Handle(nil),
			busGetError: errors.New("error"),
			busProxyNew: dbus.Handle(nil),
		},
		"error ProxyNew": {
			busGet:           dbus.Handle(nil),
			busProxyNew:      dbus.Handle(nil),
			busProxyNewError: errors.New("error"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			dbusAPI := &dbus_mocks.DBusAPI{}
			defer dbusAPI.AssertExpectations(t)

			dbusAPI.On("BusGet",
				uint(dbus.GBusTypeSystem),
			).Return(tc.busGet, tc.busGetError)

			if tc.busGetError == nil {
				dbusAPI.On("BusProxyNew",
					tc.busGet,
					DBusObjectName,
					DBusObjectPath,
					DBusInterfaceName,
				).Return(tc.busProxyNew, tc.busProxyNewError)
			}

			client, err := NewClient(dbusAPI, DBusObjectName, DBusObjectPath, DBusInterfaceName)
			if tc.busGetError != nil {
				assert.Error(t, err, tc.busGetError)
			} else if tc.busProxyNewError != nil {
				assert.Error(t, err, tc.busProxyNewError)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)

			}
		})
	}
}

func TestAuthClientGetJWTToken(t *testing.T) {
	const JWTTokenValue = "value"

	testCases := map[string]struct {
		busProxyCallError error
		result            string
	}{
		"ok": {
			result: JWTTokenValue,
		},
		"error": {
			busProxyCallError: errors.New("error"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			response := &dbus_mocks.DBusCallResponse{}
			defer response.AssertExpectations(t)

			if tc.busProxyCallError == nil {
				response.On("GetTwoStrings").Return(JWTTokenValue, "")
			}

			dbusAPI := &dbus_mocks.DBusAPI{}
			defer dbusAPI.AssertExpectations(t)

			dbusAPI.On("BusGet",
				uint(dbus.GBusTypeSystem),
			).Return(dbus.Handle(nil), nil)

			dbusAPI.On("BusProxyNew",
				dbus.Handle(nil),
				DBusObjectName,
				DBusObjectPath,
				DBusInterfaceName,
			).Return(dbus.Handle(nil), nil)

			client, err := NewClient(dbusAPI,
				DBusObjectName,
				DBusObjectPath,
				DBusInterfaceName,
			)
			assert.NoError(t, err)
			assert.NotNil(t, client)

			dbusAPI.On("BusProxyCall",
				dbus.Handle(nil),
				DBusMethodNameGetJwtToken,
				nil,
				DBusMethodTimeoutInMilliSeconds,
			).Return(response, tc.busProxyCallError)

			if tc.busProxyCallError != nil {
				c := make(chan []dbus.SignalParams)
				close(c)
				dbusAPI.On("GetChannelForSignal",
					DBusSignalNameJwtTokenStateChange,
				).Return(c, nil)
			}
			value, err := client.Authenticate(ctx)
			if tc.busProxyCallError != nil {
				assert.Error(t, err, tc.busProxyCallError)
			} else {
				if assert.NoError(t, err) {
					assert.Equal(t, value.Token, JWTTokenValue)
				}
			}
		})
	}
}

func TestAuthClientFetchJWTToken(t *testing.T) {
	const returnValue = true

	testCases := map[string]struct {
		busProxyCallError error
		result            *api.Authz
	}{
		"ok": {
			result: &api.Authz{},
		},
		"error": {
			busProxyCallError: errors.New("error"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			response := &dbus_mocks.DBusCallResponse{}
			defer response.AssertExpectations(t)

			if tc.busProxyCallError == nil {
				response.On("GetBoolean").Return(returnValue)
			}

			dbusAPI := &dbus_mocks.DBusAPI{}
			defer dbusAPI.AssertExpectations(t)

			dbusAPI.On("BusGet",
				uint(dbus.GBusTypeSystem),
			).Return(dbus.Handle(nil), nil)
			dbusAPI.On("BusProxyNew",
				dbus.Handle(nil),
				DBusObjectName,
				DBusObjectPath,
				DBusInterfaceName,
			).Return(dbus.Handle(nil), nil)
			dbusAPI.On("BusProxyCall",
				dbus.Handle(nil),
				DBusMethodNameFetchJwtToken,
				nil,
				DBusMethodTimeoutInMilliSeconds,
			).Return(response, tc.busProxyCallError)

			client, err := NewClient(
				dbusAPI,
				DBusObjectName,
				DBusObjectPath,
				DBusInterfaceName,
			)
			assert.NoError(t, err)
			assert.NotNil(t, client)

			value, err := client.FetchJWTToken()
			if tc.busProxyCallError != nil {
				assert.Error(t, err, tc.busProxyCallError)
			} else {
				assert.Equal(t, value, returnValue)
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthClientWaitForJwtTokenStateChange(t *testing.T) {
	testCases := map[string]struct {
		result *api.Authz
		params []dbus.SignalParams
		err    error
	}{
		"ok-no-params": {
			result: nil,
			err:    fmt.Errorf("insufficient number of parameters (0) received from dbus API"),
		},
		"ok-with-params": {
			result: &api.Authz{
				Token:     "the token",
				ServerURL: "https://localhost:1234",
			},
			params: []dbus.SignalParams{
				{
					ParamType: "s",
					ParamData: "the token",
				},
				{
					ParamType: "s",
					ParamData: "https://localhost:1234",
				},
			},
			err: nil,
		},
		"error": {
			err: errors.New("error"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			dbusAPI := &dbus_mocks.DBusAPI{}
			defer dbusAPI.AssertExpectations(t)
			dbusAPI.On("BusGet",
				uint(dbus.GBusTypeSystem),
			).Return(dbus.Handle(nil), nil)

			dbusAPI.On("BusProxyNew",
				dbus.Handle(nil),
				DBusObjectName,
				DBusObjectPath,
				DBusInterfaceName,
			).Return(dbus.Handle(nil), nil)

			c := make(chan []dbus.SignalParams, 1)
			dbusAPI.On("GetChannelForSignal",
				DBusSignalNameJwtTokenStateChange,
			).Run(func(_ mock.Arguments) {
				if tc.params != nil {
					c <- tc.params
				} else {
					close(c)
				}
			}).Return(c, tc.err)

			client, err := NewClient(
				dbusAPI,
				DBusObjectName,
				DBusObjectPath,
				DBusInterfaceName,
			)
			assert.NoError(t, err)
			assert.NotNil(t, client)

			params, err := client.waitForAuthStateChange(ctx)
			if tc.err != nil {
				assert.Error(t, err, tc.err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.result, params)
			}
		})
	}
}
