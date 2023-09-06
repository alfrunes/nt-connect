DESTDIR ?= /
prefix ?= $(DESTDIR)
bindir=/usr/bin
datadir ?= /usr/share
sysconfdir ?= /etc
systemd_unitdir ?= /lib/systemd

GO ?= go
GOFMT ?= gofmt
GOCYCLO ?= gocyclo
V ?=
PKGS = $(shell go list ./...)
PKGFILES = $(shell find . \( -path ./vendor \) -prune \
		-o -type f -name '*.go' -print)
PKGFILES_notest = $(shell echo $(PKGFILES) | tr ' ' '\n' | grep -v '_test.go' )
GOCYCLO_LIMIT ?= 15

VERSION = $(shell git describe --tags --dirty --exact-match 2>/dev/null || git rev-parse --short HEAD)

GO_LDFLAGS = \
	-ldflags "-X github.com/northerntechhq/nt-connect/config.Version=$(VERSION)"

ifeq ($(V),1)
BUILDV = -v
endif

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

nt-connect: $(PKGFILES)
	@$(GO) build $(GO_LDFLAGS) $(BUILDV) $(BUILDTAGS)

install: install-bin install-systemd

install-bin: nt-connect
	@install -m 755 -d $(prefix)$(bindir)
	@install -m 755 nt-connect $(prefix)$(bindir)/

install-conf:
	@install -m 755 -d $(prefix)$(sysconfdir)/nt-connect
	@install -m 600 examples/nt-connect.conf $(prefix)$(sysconfdir)/nt-connect/

install-systemd:
	@install -m 755 -d $(prefix)$(systemd_unitdir)/system
	@install -m 0644 support/nt-connect.service $(prefix)$(systemd_unitdir)/system/

uninstall: uninstall-bin uninstall-systemd

uninstall-bin:
	@rm -f $(prefix)$(bindir)/nt-connect
	@-rmdir -p $(prefix)$(bindir)

uninstall-systemd:
	@rm -f $(prefix)$(systemd_unitdir)/system/nt-connect.service
	@-rmdir -p $(prefix)$(systemd_unitdir)/system

check: test extracheck

test:
	@$(GO) test $(BUILDV) $(PKGS)

extracheck: gofmt govet godeadcode govarcheck gocyclo
	@echo "All extra-checks passed!"

gofmt:
	@echo "-- checking if code is gofmt'ed"
	@if [ -n "$$($(GOFMT) -d $(PKGFILES))" ]; then \
		"$$($(GOFMT) -d $(PKGFILES))" \
		echo "-- gofmt check failed"; \
		/bin/false; \
	fi

govet:
	@echo "-- checking with govet"
	@$(GO) vet -unsafeptr=false

godeadcode:
	@echo "-- checking for dead code"
	@deadcode -ignore version.go:Version

govarcheck:
	@echo "-- checking with varcheck"
	@varcheck ./...

gocyclo:
	@echo "-- checking cyclometric complexity > $(GOCYCLO_LIMIT)"
	@$(GOCYCLO) -over $(GOCYCLO_LIMIT) $(PKGFILES_notest)

cover: coverage
	@$(GO) tool cover -func=coverage.txt

htmlcover: coverage
	@$(GO) tool cover -html=coverage.txt

coverage:
	@rm -f coverage.txt
	@$(GO) test -coverprofile=coverage-tmp.txt -coverpkg=./... ./...
	@if [ -f coverage-missing-subtests.txt ]; then \
		echo 'mode: set' > coverage.txt; \
		cat coverage-tmp.txt coverage-missing-subtests.txt | grep -v 'mode: set' >> coverage.txt; \
	else \
		mv coverage-tmp.txt coverage.txt; \
	fi
	@rm -f coverage-tmp.txt coverage-missing-subtests.txt

.PHONY: build
.PHONY: clean
.PHONY: get-tools
.PHONY: test
.PHONY: check
.PHONY: extracheck
.PHONY: cover
.PHONY: htmlcover
.PHONY: coverage
.PHONY: install
.PHONY: install-bin
.PHONY: install-systemd
.PHONY: uninstall
.PHONY: uninstall-bin
.PHONY: uninstall-systemd
