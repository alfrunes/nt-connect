GO ?= go
BUILDFLAGS ?=
PKGS = $(shell go list ./...)
PKGFILES = $(shell find . \( -path ./vendor \) -prune \
		-o -type f -name '*.go' -print)
VERSION = $(shell git describe --tags --dirty)
GOARCH ?= $(shell go env GOARCH)
GOOS ?= $(shell go env GOOS)

GO_LDFLAGS = -s -X github.com/northerntechhq/nt-connect/config.Version=$(VERSION)

binary = nt-connect

prefix ?= /usr/local
exec_prefix ?= $(prefix)
ifneq ($(DESTDIR),)
prefix = $(DESTDIR)
exec_prefix = $(DESTDIR)/usr
datadir = $(DESTDIR)/usr/share
endif
bindir ?= $(exec_prefix)/bin
datadir ?= $(prefix)/share
libdir ?= $(exec_prefix)/lib
localstatedir ?= $(prefix)/var
sysconfdir ?= $(prefix)/etc

TAGS =
ifeq ($(LOCAL),1)
TAGS += local
endif

ifneq ($(TAGS),)
BUILDTAGS = -tags '$(TAGS)'
endif

build: nt-connect

clean:
	@$(GO) clean
	@-rm -f coverage.txt
	@rm -rf dist

install: install-bin install-systemd
	@install -m 600 -D support/nt-connect.json $(sysconfdir)/nt-connect/nt-connect.json
	@install -m 755 -D support/inventory.sh $(datadir)/nt-connect/inventory.sh
	@install -m 755 -d  $(localstatedir)/lib/nt-connect

nt-connect $(bindir)/nt-connect: $(PKGFILES)
	@$(GO) build -ldflags "$(GO_LDFLAGS)" $(BUILDFLAGS) $(BUILDTAGS) -o $@

install-bin: $(bindir)/nt-connect

install-systemd:
	@install -m 0644 -D support/nt-connect.service $(libdir)/systemd/system/nt-connect.service

uninstall: uninstall-bin uninstall-conf uninstall-systemd

uninstall-bin:
	@rm -f $(bindir)/nt-connect

uninstall-systemd:
	@rm -f $(libdir)/systemd/system/nt-connect.service

uninstall-conf:
	@rm -f $(datadir)/nt-connect/inventory.sh
	@rm -f $(sysconfdir)/nt-connect/nt-connect.json
	@rmdir $(datadir)/nt-connect
	@rmdir $(sysconfdir)/nt-connect
	@rmdir $(localstatedir)/lib/nt-connect

test:
	@$(GO) test $(BUILDFLAGS) $(PKGS)

coverage:
	@$(GO) test -coverprofile=coverage.txt -coverpkg=./... ./...

.PHONY:
	build
	dist
	clean
	install
	install-bin
	install-conf
	install-systemd
	uninstall
	uninstall-bin
	uninstall-systemd
	uninstall-conf
	check
	test
	extracheck
	gofmt
	govet
	godeadcode
	govarcheck
	gocyclo
	coverage
