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

//go:build dbus
// +build dbus

package app

import (
	log "github.com/sirupsen/logrus"

	"github.com/northerntechhq/nt-connect/api"
	apidbus "github.com/northerntechhq/nt-connect/api/dbus"
	"github.com/northerntechhq/nt-connect/client/dbus"
)

func getDBUSClient(done <-chan struct{}) (api.Client, error) {
	dbusAPI, err := dbus.GetDBusAPI()
	if err != nil {
		return nil, err
	}

	//new dbus client
	apiClient, err := apidbus.NewClient(
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
		<-done
		dbusAPI.MainLoopQuit(loop)
	}()
	return apiClient, nil
}
