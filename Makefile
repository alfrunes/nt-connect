#!/usr/bin/make -f

GO ?= go
BUILDFLAGS ?=
PKGS = $(shell go list ./...)
PKGFILES = $(shell find . \( -path ./vendor \) -prune \
		-o -type f -name '*.go' -print)
VERSION = $(shell git describe --tags --dirty)
GOARCH ?= $(shell go env GOARCH)
GOOS ?= $(shell go env GOOS)
GO_LDFLAGS = -s -X github.com/northerntechhq/nt-connect/config.Version=$(VERSION)
DESTDIR ?= ""

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

govariant ?= ""
ifeq ("$(GOARCH)","arm")
	govariant = "v$(shell go env GOARM)"
endif


.PHONY: build
build: nt-connect

.PHONY: dist
dist: DESTDIR=dist/nt-connect_$(VERSION)_$(GOOS)_$(GOARCH)$(govariant)
dist:
	@make DESTDIR=$(DESTDIR) -B install
	@tar --remove-files -C $(DESTDIR) -czf $(DESTDIR).tar.gz .

.PHONY: clean
clean:
	@$(GO) clean
	@-rm -f coverage.txt
	@rm -rf dist

.PHONY: install
install: $(bindir)/nt-connect install-systemd
	@install -m 600 -D support/nt-connect.json $(sysconfdir)/nt-connect/nt-connect.json
	@install -m 755 -D support/inventory.sh $(datadir)/nt-connect/inventory.sh
	@install -m 755 -d  $(localstatedir)/lib/nt-connect

nt-connect $(bindir)/nt-connect: $(PKGFILES)
	@$(GO) build -ldflags "$(GO_LDFLAGS)" $(BUILDFLAGS) $(BUILDTAGS) -o $@

.PHONY: install-systemd
install-systemd:
	@install -m 0644 -D support/nt-connect.service $(libdir)/systemd/system/nt-connect.service

.PHONY: uninstall
uninstall: uninstall-bin uninstall-conf uninstall-systemd

.PHONY: uninstall-bin
uninstall-bin:
	@rm -f $(bindir)/nt-connect

.PHONY: uninstall-systemd
uninstall-systemd:
	@rm -f $(libdir)/systemd/system/nt-connect.service

.PHONY: uninstall-conf
uninstall-conf:
	@rm -f $(datadir)/nt-connect/inventory.sh
	@rm -f $(sysconfdir)/nt-connect/nt-connect.json
	@rmdir $(datadir)/nt-connect
	@rmdir $(sysconfdir)/nt-connect
	@rmdir $(localstatedir)/lib/nt-connect

.PHONY: test
test:
	@$(GO) test $(BUILDFLAGS) $(PKGS)

.PHONY: coverage
coverage:
	@$(GO) test -coverprofile=coverage.txt -coverpkg=./... ./...
