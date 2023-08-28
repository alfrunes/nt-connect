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

package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

type ED25519Signer ed25519.PrivateKey

func (p ED25519Signer) Sign(rand io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	return ed25519.Sign(ed25519.PrivateKey(p), message), nil
}

func (p ED25519Signer) Public() crypto.PublicKey {
	return ed25519.PrivateKey(p).Public()
}

func LoadPrivateKey(pkeyPEM []byte) (crypto.Signer, error) {
	var err error
	block, _ := pem.Decode(pkeyPEM)
	var pkey crypto.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		pkey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		pkey, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		pkey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, err
	}
	// ed25519 does not use SHA256 digest
	if eddie, ok := pkey.(ed25519.PrivateKey); ok {
		pkey = ED25519Signer(eddie)
	}
	privateKey, ok := pkey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("invalid private key type")
	}
	return privateKey, nil
}

type KeyType string

const (
	KeyTypeRSA2048   KeyType = "rsa2048"
	KeyTypeRSA3072   KeyType = "rsa3072"
	KeyTypeRSA4096   KeyType = "rsa4096"
	KeyTypeSECP256R1 KeyType = "secp256r1"
	KeyTypeSECP384R1 KeyType = "secp384r1"
	KeyTypeSECP521R1 KeyType = "secp521r1"
	KeyTypeED25519   KeyType = "ed25519"
)

func ParseKeyType(s string) (KeyType, error) {
	ret := KeyType(s)
	switch ret {
	case KeyTypeRSA2048:
	case KeyTypeRSA3072:
	case KeyTypeRSA4096:
	case KeyTypeSECP256R1:
	case KeyTypeSECP384R1:
	case KeyTypeSECP521R1:
	case KeyTypeED25519:
	default:
		return ret, fmt.Errorf("invalid key type: %s", s)
	}
	return ret, nil
}

func GeneratePrivateKey(keyType KeyType) (crypto.Signer, error) {
	var (
		pkey crypto.Signer
		err  error
	)
	switch keyType {
	case KeyTypeRSA2048:
		pkey, err = rsa.GenerateKey(rand.Reader, 2048)
	case KeyTypeRSA3072:
		pkey, err = rsa.GenerateKey(rand.Reader, 3072)
	case KeyTypeRSA4096:
		pkey, err = rsa.GenerateKey(rand.Reader, 4096)
	case KeyTypeSECP256R1:
		pkey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyTypeSECP384R1:
		pkey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyTypeSECP521R1:
		pkey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case KeyTypeED25519:
		_, pkey, err = ed25519.GenerateKey(rand.Reader)

		pkey = ED25519Signer(pkey.(ed25519.PrivateKey))
	default:
		err = fmt.Errorf("invalid key type: %s", keyType)
	}
	if err != nil {
		return nil, err
	}
	return pkey, nil
}

func SavePrivateKey(pkey crypto.Signer, path string) error {
	der, err := x509.MarshalPKCS8PrivateKey(pkey)
	if err != nil {
		return fmt.Errorf("failed to serialize private key: %w", err)
	}
	fd, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err == nil {
		defer fd.Close()
		err = pem.Encode(fd, &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		})
	}
	if err != nil {
		return fmt.Errorf("failed to write private key file: %w", err)
	}
	return nil
}
