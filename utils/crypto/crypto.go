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
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
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

var ErrNoCerts = errors.New("no certificates found")

var (
	certStart = []byte("-----BEGIN CERTIFICATE-----")
	certEnd   = []byte("-----END CERTIFICATE-----")
)

func splitCerts(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.Index(data, certStart); i > 0 {
		return i, data[:i], nil
	} else if i := bytes.Index(data, certEnd); i >= 0 {
		i += len(certEnd)
		return i, data[:i], nil
	} else if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func LoadCertificates(filepath string) (certs *x509.CertPool, err error) {
	const (
		InitialBufSize = 32 * 1024        // 32 KiB
		MaxPEMSize     = 512 * 1024       // 512 KiB
		MaxFileSize    = 32 * 1024 * 1024 // 32 MiB
		PEMCertificate = "CERTIFICATE"
	)
	fd, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("config: CACertificate not found: %w", err)
	}
	defer fd.Close()
	var (
		scanBuf [InitialBufSize]byte
		n       int
	)
	certs = x509.NewCertPool()
	lr := io.LimitReader(fd, MaxFileSize)
	s := bufio.NewScanner(lr)
	s.Buffer(scanBuf[:], MaxPEMSize)
	s.Split(splitCerts)
	for err == nil && s.Scan() {
		p, _ := pem.Decode(s.Bytes())
		if p == nil || p.Type != PEMCertificate {
			continue
		}
		var cert *x509.Certificate
		cert, err = x509.ParseCertificate(p.Bytes)
		if err != nil {
			break
		}
		n++
		certs.AddCert(cert)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	} else if err = s.Err(); err != nil {
		return nil, err
	} else if n <= 0 {
		return nil, &os.PathError{
			Op:   "LoadCertificates",
			Path: filepath,
			Err:  ErrNoCerts,
		}
	}
	return certs, nil
}
