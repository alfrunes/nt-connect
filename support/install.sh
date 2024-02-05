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
HAS_SYSTEMD="false"
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
	--arch ARCH	-a ARCH	Override default system ARCHitecture.
	--version VER	-v VER	VERsion of nt-connect to install.
	--uninstall		Uninstall nt-connect.
	--help		-h	Display this help text.

Environment variables:
	SESSION_TOKEN	Authorized user session token (skips authentication).
	SERVER_URL	The upstream server URL to connect to.
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

check_dependencies() {
	if ! command -v jq > /dev/null; then
		echo "This script needs jq >= 1.4 to configure your device" 1>&2
		exit 1;
	elif ! command -v curl > /dev/null; then
		echo "This script needs curl to setup your device" 1>&2
		exit 1;
	fi
	if command -v systemctl > /dev/null; then
		HAS_SYSTEMD="true"
	else
		HAS_SYSTEMD="false"
	fi
}

install() {
	local release_name="nt-connect_${VERSION}_${OS}_${ARCH}"
	local dlpath="/releases/download/${VERSION}/${release_name}.tar.gz"
	mkdir -p "${INSTALL_DIR}"
	if test ! -f "${INSTALL_DIR}/${release_name}.tar.gz"; then
		curl -s -f -L "https://github.com/NorthernTechHQ/nt-connect${dlpath}" \
			-o "${INSTALL_DIR}/${release_name}.tar.gz"
	fi
	if test -d /etc/nt-connect; then
		tar -xzf "${INSTALL_DIR}/${release_name}.tar.gz" \
			--exclude ./etc/nt-connect \
			-C /
	else
		tar -xzf "${INSTALL_DIR}/${release_name}.tar.gz" -C /
	fi
	echo "nt-connect installed successfully!"
}

authenticate() {
	local USERNAME=""
	local PASSWORD=""
	printf 'Enter username: ' 1>&2
	read USERNAME
	printf 'Enter password: ' 1>&2
	stty -echo
	read PASSWORD
	stty echo

	code=$(curl -w '%{http_code}' \
		-s \
		-u "${USERNAME}:${PASSWORD}" \
		-X POST \
		-o "${INSTALL_DIR}/authz.jwt" \
		"${SERVER_URL}/api/management/v1/useradm/auth/login")
	if ! test $code -eq 200; then
		if test $code -eq 401; then
			printf "Authentication failed\n" 1>&2
			exit 1
		else
			printf "Unknown error attempting to login\n" 1>&2
			exit 1
		fi
	fi
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
	echo "Configuring device..."
	/usr/bin/nt-connect bootstrap 2>&1 1> /dev/null

	# Prompt for server URL if not set.
	if test -z "${SERVER_URL}"; then
		printf 'Enter server url [https://app.alvaldi.com]: '
		read SERVER_URL
		if test -z "${SERVER_URL}"; then
			SERVER_URL="https://app.alvaldi.com"
		fi
	fi
	# Prompt for credentials if SESSION_TOKEN is not set
	if test -z "$SESSION_TOKEN"; then
		authenticate
		trap logout INT QUIT TERM EXIT
	fi
	# Fetch tenant token if not set
	if test -z "$TENANT_TOKEN"; then
		TENANT_TOKEN=$(curl -s -f "${SERVER_URL}/api/management/v1/tenantadm/user/tenant" \
			-H "Authorization: Bearer ${SESSION_TOKEN}" | \
			jq -r .tenant_token)
	fi
	umask 066

	# Update the configuration by providing tenant token and server URL.
	if ! jq ".API.TenantToken=\"${TENANT_TOKEN}\" | .API.ServerURL=\"${SERVER_URL}\"" \
		/etc/nt-connect/nt-connect.json > \
		/etc/nt-connect/nt-connect.json.new; then
		echo "Failed to bootstrap nt-connect configuration";
		exit 1;
	fi
	cp -n /etc/nt-connect/nt-connect.json /etc/nt-connect/nt-connect.json.bak
	mv /etc/nt-connect/nt-connect.json.new \
		/etc/nt-connect/nt-connect.json

	# Authorize device
	cat /var/lib/nt-connect/identity.json | \
		jq '.identity_data = (.id_data | fromjson) | del(.id_data)' | \
		curl -s "${SERVER_URL}/api/management/v2/devauth/devices" \
		-H 'Content-Type: application/json' \
		-H "Authorization: Bearer ${SESSION_TOKEN}" -d '@-' > /dev/null

	echo "nt-connect initialized successfully!"

	# Enable and start systemd service
	if test "$HAS_SYSTEMD" = "true"; then
		systemctl enable nt-connect
		systemctl start nt-connect
	else
		echo "WARNING: nt-connect is not running - systemd not found"
		echo "To start the daemon, run:"
		echo "\t/usr/bin/nt-connect daemon"
	fi
}

uninstall() {
	if test "$HAS_SYSTEMD" = "true"; then
		systemctl stop nt-connect
		systemctl disable nt-connect
	fi

	local release_name="nt-connect_${VERSION}_${OS}_${ARCH}"
	for file in $(tar --list --file "${INSTALL_DIR}/${release_name}.tar.gz"); do
		if test -f "${file#.}"; then
			rm -f ${file#.}
		fi
	done
}

parse_args "$@"
check_dependencies
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
