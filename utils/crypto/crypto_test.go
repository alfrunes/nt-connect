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
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadCertificates(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	type TestCase struct {
		CertificatePEM string
		assert.ErrorAssertionFunc
	}
	for name, testCase := range map[string]TestCase{
		"ok": {
			CertificatePEM: TestDataSelfSignedCertificate,
		},
		"error/invalid certificate": {
			CertificatePEM: TestDataInvalidCertificate,
			ErrorAssertionFunc: func(t assert.TestingT, err error, i ...interface{}) bool {

				return assert.EqualError(t, err, "x509: malformed certificate", i...)
			},
		},
		"error/no certificates": {
			CertificatePEM: "garbage...",
			ErrorAssertionFunc: func(t assert.TestingT, err error, i ...interface{}) bool {

				var pathErr *os.PathError
				if assert.ErrorAs(t, err, &pathErr, i...) {
					return assert.ErrorIs(t, err, ErrNoCerts, i...)
				}
				return false
			},
		},
	} {
		tc := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var filename string
			fd, err := os.CreateTemp(dir, "certificate-*.pem")
			if err == nil {
				filename = fd.Name()
				_, err = fd.Write([]byte(tc.CertificatePEM))
				errClose := fd.Close()
				if err == nil {
					err = errClose
				}
			}
			if err != nil {
				t.Errorf("failed to create testfile: %s", err.Error())
				t.FailNow()
			}

			conf, err := LoadCertificates(filename)
			if tc.ErrorAssertionFunc != nil {
				tc.ErrorAssertionFunc(t, err)
			} else if assert.NoError(t, err) {
				assert.NotNil(t, conf)
			}
		})
	}
	t.Run("error/file not found", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "not_found")
		_, err := LoadCertificates(path)
		if assert.Error(t, err) {
			assert.ErrorIs(t, err, fs.ErrNotExist)
		}
	})
}
