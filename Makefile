GO = go
GOBUILD = $(GO) build
GOTEST = $(GO) test

BINARY_NAME=crowdsec-firewall-bouncer
TARBALL_NAME=$(BINARY_NAME).tgz

ifdef BUILD_STATIC
$(warning WARNING: The BUILD_STATIC variable is deprecated and has no effect. Builds are static by default now.)
endif

# Versioning information can be overridden in the environment
BUILD_VERSION?=$(shell git describe --tags)
BUILD_TIMESTAMP?=$(shell date +%F"_"%T)
BUILD_TAG?=$(shell git rev-parse HEAD)

LD_OPTS_VARS=\
-X 'github.com/crowdsecurity/go-cs-lib/version.Version=$(BUILD_VERSION)' \
-X 'github.com/crowdsecurity/go-cs-lib/version.BuildDate=$(BUILD_TIMESTAMP)' \
-X 'github.com/crowdsecurity/go-cs-lib/version.Tag=$(BUILD_TAG)'

ifneq (,$(DOCKER_BUILD))
LD_OPTS_VARS += -X 'github.com/crowdsecurity/go-cs-lib/version.System=docker'
endif

export CGO_ENABLED=0
export LD_OPTS=-ldflags "-s -extldflags '-static' $(LD_OPTS_VARS)" \
	-trimpath -tags netgo

.PHONY: all
all: build test

# same as "$(MAKE) -f debian/rules clean" but without the dependency on debhelper
.PHONY: clean-debian
clean-debian:
	@$(RM) -r debian/crowdsec-firewall-bouncer-iptables
	@$(RM) -r debian/crowdsec-firewall-bouncer-nftables
	@$(RM) -r debian/files
	@$(RM) -r debian/.debhelper
	@$(RM) -r debian/*.substvars
	@$(RM) -r debian/*-stamp

.PHONY: clean-rpm
clean-rpm:
	@$(RM) -r rpm/BUILD
	@$(RM) -r rpm/BUILDROOT
	@$(RM) -r rpm/RPMS
	@$(RM) -r rpm/SOURCES/*.tar.gz
	@$(RM) -r rpm/SRPMS

# Remove everything including all platform binaries and tarballs
.PHONY: clean
clean: clean-release-dir clean-debian clean-rpm
	@$(RM) $(BINARY_NAME)
	@$(RM) $(TARBALL_NAME)
	@$(RM) -r $(BINARY_NAME)-*	# platform binary name and leftover release dir
	@$(RM) $(BINARY_NAME)-*.tgz	# platform release file

#
# Build binaries
#

.PHONY: binary
binary:
	$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME)

.PHONY: build
build: clean binary

#
# Unit and integration tests
#

.PHONY: lint
lint:
	golangci-lint run

.PHONY: test
test:
	@$(GOTEST) $(LD_OPTS) ./...

.PHONY: func-tests
func-tests: build
	pipenv install --dev
	pipenv run pytest -v

#
# Build release tarballs
#

RELDIR = $(BINARY_NAME)-$(BUILD_VERSION)

.PHONY: vendor
vendor: vendor-remove
	$(GO) mod vendor
	tar czf vendor.tgz vendor
	tar --create --auto-compress --file=$(RELDIR)-vendor.tar.xz vendor

.PHONY: vendor-remove
vendor-remove:
	$(RM) -r vendor vendor.tgz *-vendor.tar.xz

# Called during platform-all, to reuse the directory for other platforms
.PHONY: clean-release-dir
clean-release-dir:
	@$(RM) -r $(RELDIR)

.PHONY: tarball
tarball: binary
	@if [ -z $(BUILD_VERSION) ]; then BUILD_VERSION="local" ; fi
	@if [ -d $(RELDIR) ]; then echo "$(RELDIR) already exists, please run 'make clean' and retry" ;  exit 1 ; fi
	@echo Building Release to dir $(RELDIR)
	@mkdir -p $(RELDIR)/scripts
	@cp $(BINARY_NAME) $(RELDIR)/
	@cp -R ./config $(RELDIR)/
	@cp ./scripts/install.sh $(RELDIR)/
	@cp ./scripts/uninstall.sh $(RELDIR)/
	@cp ./scripts/upgrade.sh $(RELDIR)/
	@cp ./scripts/_bouncer.sh $(RELDIR)/scripts/
	@chmod +x $(RELDIR)/install.sh
	@chmod +x $(RELDIR)/uninstall.sh
	@chmod +x $(RELDIR)/upgrade.sh
	@tar cvzf $(TARBALL_NAME) $(RELDIR)

.PHONY: release
release: clean tarball

#
# Build binaries and release tarballs for all platforms
#

.PHONY: platform-all
platform-all: clean
	python3 .github/release.py run-build $(BINARY_NAME)
