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

// openssl req -x509 -sha256 -nodes \
// -days $((365 * 100)) \
// -newkey ec:<(openssl ecparam -name secp384r1) \
// -keyout /dev/null \
// -subj "/CN=dev.alvaldi.com" \
// -addext "extendedKeyUsage = serverAuth" \
// -addext "subjectAltName = DNS:dev.alvaldi.com"
const TestDataSelfSignedCertificate = `
-----BEGIN CERTIFICATE-----
MIIB+zCCAYGgAwIBAgIUPXyw1VSmvXOgBB0ctGpWa/2OvnYwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPZGV2LmFsdmFsZGkuY29tMCAXDTIzMDkwMTE1MzgwNloYDzIx
MjMwODA4MTUzODA2WjAaMRgwFgYDVQQDDA9kZXYuYWx2YWxkaS5jb20wdjAQBgcq
hkjOPQIBBgUrgQQAIgNiAAS8hPNlLruaGqZcrarsl/yugB6WzifidooPzeQjMx+x
Ssyk2y5FxrpBQqhre15t5ylqJE9+Qh5vrJpzjI4hE12Axxdsw9kvkYnxl80NbC3L
CFfGx11XJacmv7phXMkKtB+jgYUwgYIwHQYDVR0OBBYEFBnuV3q6gbmJ5RyNwNVw
ArHpl3ZHMB8GA1UdIwQYMBaAFBnuV3q6gbmJ5RyNwNVwArHpl3ZHMA8GA1UdEwEB
/wQFMAMBAf8wEwYDVR0lBAwwCgYIKwYBBQUHAwEwGgYDVR0RBBMwEYIPZGV2LmFs
dmFsZGkuY29tMAoGCCqGSM49BAMCA2gAMGUCMD8Bk0oJ/Htbdb6qRDY5LHcKt1hz
wiyQm++QJo5Rnj129hSbeC8nkqnhJ+MusIrHgQIxAM2iAQGb9JxrHLJo2ICc6YJM
fjNuL4kfuuyfejv5tJS9ZMJwQBjqS2cJKlQibwPDxg==
-----END CERTIFICATE-----
`

const TestDataInvalidCertificate = `
-----BEGIN CERTIFICATE-----
MIIB+zCCAYGgAwIBAgIUPXyw1VSmvXOgBB0ctGpWa/2OvnYwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPZGV2LmFsdmFsZGkuY29tMCAXDTIzMDkwMTE1MzgwNloYDzIx
MjMwODA4MTUzODA2WjAaMRgwFgYDVQQDDA9kZXYuYWx2YWxkaS5jb20wdjAQBgcq
hkjOPQIBBgUrgQQAIgNiAAS8hPNlLruaGqZcrarsl/yugB6WzifidooPzeQjMx+x
Ssyk2y5FxrpBQqhre15t5ylqJE9+Qh5vrJpzjI4hE12Axxdsw9kvkYnxl80NbC3L
CFfGx11XJacmv7phXMkKtB+jgYUwgYIwHQYDVR0OBBYEFBnuV3q6gbmJ5RyNwNVw
ArHpl3ZHMB8GA1UdIwQYMBaAFBnuV3q6gbmJ5RyNwNVwArHpl3ZHMA8GA1UdEwEB
/wQFMAMBAf8wEwYDVR0lBAwwCgYIKwYBBQUHAwEwGgYDVR0RBBMwEYIPZGV2LmFs
dmFsZGkuY29tMAoGCCqGSM49BAMCA2gAMGUCMD8Bk0oJ/Htbdb6qRDY5LHcKt1hz
fjNuL4kfuuyfejv5tJS9ZMJwQBjqS2cJKlQibwPDxg==
-----END CERTIFICATE-----
`
