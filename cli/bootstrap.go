// Copyright 2021 Northern.tech AS
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

package cli

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/urfave/cli/v2"

	"github.com/northerntechhq/nt-connect/api"
	"github.com/northerntechhq/nt-connect/config"
	cryptoutil "github.com/northerntechhq/nt-connect/utils/crypto"
	log "github.com/sirupsen/logrus"
)

func bootstrap(c *cli.Context, cfg *config.MenderShellConfig) error {
	var err error
	switch cfg.APIConfig.APIType {
	case config.APITypeHTTP:
		var (
			pkey     crypto.Signer
			identity *api.Identity
		)
		if _, err = os.Stat(cfg.APIConfig.PrivateKeyPath); err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf(
					"unexpected error checking file existance: %w",
					err,
				)
			}
		} else if err == nil {
			b, err := os.ReadFile(cfg.APIConfig.PrivateKeyPath)
			if err == nil {
				pkey, err = cryptoutil.LoadPrivateKey(b)
			}
			if err != nil {
				return fmt.Errorf("failed to load private key: %w", err)
			}
		}
		if os.IsNotExist(err) || c.Bool("force") {
			kt, err := cryptoutil.ParseKeyType(c.String("key-type"))
			if err != nil {
				return err
			}
			pkey, err = cryptoutil.GeneratePrivateKey(kt)
			if err != nil {
				return fmt.Errorf("failed to generate private key: %w", err)
			}
			err = cryptoutil.SavePrivateKey(pkey, cfg.APIConfig.PrivateKeyPath)
			if err != nil {
				return fmt.Errorf("failed to save private key: %w", err)
			}
		}
		if _, err = os.Stat(cfg.APIConfig.IdentityPath); err != nil &&
			!os.IsNotExist(err) {
			return fmt.Errorf("unexpected error checking file existance: %w", err)
		}
		if os.IsNotExist(err) || c.Bool("force") {
			identity, err = generateIdentityData(
				cfg.APIConfig,
				pkey,
				c.StringSlice("extra-identity"),
			)
			if err != nil {
				return fmt.Errorf("failed to generate private key: %w", err)
			}
		} else {
			b, err := os.ReadFile(cfg.APIConfig.IdentityPath)
			if err == nil {
				err = json.Unmarshal(b, &identity)
			}
			if err != nil {
				return fmt.Errorf("failed to load identity file: %w", err)
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(identity)
		if err != nil {
			return fmt.Errorf("failed to dump identity to stdout: %w", err)
		}
	case config.APITypeDBus:
		log.Info("Authentication configured for DBus: skipping bootstrap")

	default:
		err = fmt.Errorf(
			"unknown auth type %q: skipping bootstrap",
			cfg.APIConfig.APIType,
		)
	}
	return err
}

func generateIdentityData(cfg config.APIConfig, pkey crypto.Signer, extraValues []string) (*api.Identity, error) {
	var (
		err      error
		iface    net.Interface
		identity = &api.Identity{
			TenantToken: cfg.TenantToken,
		}
		identityData = make(map[string]string, len(extraValues)+1)
	)
	pubBytes, err := x509.MarshalPKIXPublicKey(pkey.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to serialize public key: %w", err)
	}
	identity.PublicKey = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}))
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}
	for _, iface = range interfaces {
		if iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) > 0 {
			continue
		}
		identityData["mac"] = iface.HardwareAddr.String()
		break
	}

	for _, val := range extraValues {
		idx := strings.IndexByte(val, '=')
		if idx < 0 {
			return nil, fmt.Errorf(
				"malformed identity key/value pair: expected format: `key=value`",
			)
		}
		identityData[val[:idx]] = val[idx+1:]
	}

	const (
		edgeEnvHostName = "IOTEDGE_IOTHUBHOSTNAME"
		edgeEnvDeviceID = "IOTEDGE_DEVICEID"
		edgeEnvModuleID = "IOTEDGE_MODULEID"
	)
	if edgeHost, ok := os.LookupEnv(edgeEnvHostName); ok {
		identityData["iothub:hostname"] = edgeHost
		var externalID string
		if deviceID, ok := os.LookupEnv(edgeEnvDeviceID); ok {
			externalID = deviceID
			identityData["iothub:device_id"] = deviceID
		}
		if moduleID, ok := os.LookupEnv(edgeEnvModuleID); ok {
			externalID += "/" + moduleID
			identityData["iothub:module_id"] = moduleID
		}
		if externalID != "" {
			identity.ExternalID = externalID
		}
	}

	fd, err := os.OpenFile(cfg.IdentityPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity file: %w", err)
	}
	defer fd.Close()

	b, _ := json.Marshal(identityData)
	identity.Data = string(b)

	enc := json.NewEncoder(fd)
	err = enc.Encode(identity)
	if err != nil {
		return nil, fmt.Errorf("error serializing identity data: %w", err)
	}
	return identity, nil
}
