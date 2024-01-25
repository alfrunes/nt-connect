#!/bin/sh
# Copyright 2024 Northern.tech AS
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

set -e

ARCH=""
# TODO: Should we default to the latest from Github?
VERSION="v1.0.1"
INSTALL_DIR=${INSTALL_DIR:-"/var/lib/nt-connect"}
SESSION_TOKEN="${SESSION_TOKEN}"
OS="linux" # No other options at this stage

COMMAND="install"

init_defaults() {
	if test -z "$ARCH"; then
		local machine=$(uname -m)
		case "$machine" in
			x86_64*|amd64*)
				ARCH="amd64"
				;;
			aarch64*|armv8*)
				ARCH="arm64"
				;;
			armv7*)
				# ???
				ARCH="armv7"
				;;
			armv6*)
				ARCH="armv6"
				;;
			*)
				printf 'Unsupported machine type "%s"\n' "$machine" 1>&2
				exit 1
				;;
		esac
	fi
}

print_usage() {
	cat 1>&2 <<EOF
Usage:
	${0} [--version|-v <version>] [--arch|-a <arch>] [--help|-h]

Arguments:
	--arch, -a ARCH		Override default system ARCHitecture.
	--version, -v VERSION	VERSION of nt-connect to install.
	--help, -h		Display this help text.
EOF
}

parse_args() {
	while test $# -gt 0; do
		case "$1" in
			"--version"|"-v")
				shift
				VERSION=$1
				;;
			"--arch"|"-a")
				shift
				ARCH=$1
				;;
			"--uninstall"|"-u")
				COMMAND="uninstall"
				;;
			"--help"|"-h")
				print_usage
				exit 0
				;;
			*)
				printf 'Invalid argument "%s"\n' "$1" 1>&2
				print_usage
				exit 1
				;;
		esac
		shift
	done
}

install() {
	local release_name="nt-connect_${VERSION}_${OS}_${ARCH}"
	local dlpath="/releases/download/${VERSION}/${release_name}.tar.gz"
	mkdir -p "${INSTALL_DIR}"
	if test ! -f "${INSTALL_DIR}/${release_name}.tar.gz"; then
		curl -s -f -L "https://github.com/NorthernTechHQ/nt-connect${dlpath}" \
			-o "${INSTALL_DIR}/${release_name}.tar.gz"
	fi
	tar --skip-old-files -xzf "${INSTALL_DIR}/${release_name}.tar.gz" -C /
	tar -xzf "${INSTALL_DIR}/${release_name}.tar.gz" -C / -- ./usr/bin/nt-connect
}

authenticate() {
	local USERNAME=""
	local PASSWORD=""
	printf 'Enter username: ' 1>&2
	read USERNAME
	set +e
	while true; do
		printf 'Enter password: ' 1>&2
		stty -echo
		read PASSWORD
		stty echo

		code=$(curl -w '%{http_code}' \
			-f -s \
			-u "${USERNAME}:${PASSWORD}" \
			-X POST \
			-o "${INSTALL_DIR}/authz.jwt" \
			"${SERVER_URL}/api/management/v1/useradm/auth/login" || \
			true)
		if test $code -eq 200; then
			break;
		elif test $code -eq 401; then
				printf "Authentication failed\n"
				continue;
		else
				printf "Unknown error attempting to login" 2>&1
				exit 1;
		fi
	done
	echo ""
	SESSION_TOKEN=$(cat ${INSTALL_DIR}/authz.jwt)
	rm -f ${INSTALL_DIR}/authz.jwt
}

logout() {
	curl "${SERVER_URL}/api/management/v1/useradm/auth/logout" \
		-s -X POST \
		-H "Authorization: Bearer ${SESSION_TOKEN}"
}

bootstrap() {
	/usr/bin/nt-connect bootstrap 2>&1 1> /dev/null
	printf 'Enter server url [https://app.alvaldi.com]: '
	read SERVER_URL
	if test -z "${SERVER_URL}"; then
		SERVER_URL="https://app.alvaldi.com"
	fi
	if test -z "$SESSION_TOKEN"; then
		authenticate
		trap logout INT QUIT TERM EXIT
	fi
	if test -z "$TENANT_TOKEN"; then
		TENANT_TOKEN=$(curl -s -f "${SERVER_URL}/api/management/v1/tenantadm/user/tenant" \
			-H "Authorization: Bearer ${SESSION_TOKEN}" | \
			jq -r .tenant_token)
	fi
	umask 066

	# Update the configuration by providing tenant token and server URL.
	jq ".API.TenantToken=\"${TENANT_TOKEN}\" | .API.ServerURL=\"${SERVER_URL}\"" \
		/etc/nt-connect/nt-connect.json > \
		/etc/nt-connect/nt-connect.json.new
	mv --backup=numbered \
		/etc/nt-connect/nt-connect.json.new \
		/etc/nt-connect/nt-connect.json

	# Authorize device
	cat /var/lib/nt-connect/identity.json | \
		jq '.identity_data = (.id_data | fromjson) | del(.id_data)' | \
		curl -s "${SERVER_URL}/api/management/v2/devauth/devices" \
		-H 'Content-Type: application/json' \
		-H "Authorization: Bearer ${SESSION_TOKEN}" -d '@-' > /dev/null

	# Enable and start systemd service
	systemctl enable nt-connect && systemctl start nt-connect
}

uninstall() {
	systemctl stop nt-connect || true
	systemctl disable nt-connect || true

	local release_name="nt-connect_${VERSION}_${OS}_${ARCH}"
	for file in $(tar --list --file "${INSTALL_DIR}/${release_name}.tar.gz"); do
		# TODO: Clean up empty directories?
		if test -f "${file#.}"; then
			rm -f ${file#.}
		fi
	done
}

parse_args "$@"
init_defaults
case "$COMMAND" in
	uninstall)
		uninstall
		;;
	*)
		install
		bootstrap
		;;
esac
