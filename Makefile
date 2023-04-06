GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test

BINARY_NAME=crowdsec-firewall-bouncer
GO_MODULE_NAME=github.com/crowdsecurity/cs-firewall-bouncer
TARBALL_NAME=$(BINARY_NAME).tgz

ifdef BUILD_STATIC
$(warning WARNING: The BUILD_STATIC variable is deprecated and has no effect. Builds are static by default since v1.5.0.)
endif

# Versioning information can be overridden in the environment
BUILD_VERSION?=$(shell git describe --tags)
BUILD_TIMESTAMP?=$(shell date +%F"_"%T)
BUILD_TAG?=$(shell git rev-parse HEAD)

LD_OPTS_VARS=\
-X '$(GO_MODULE_NAME)/pkg/version.Version=$(BUILD_VERSION)' \
-X '$(GO_MODULE_NAME)/pkg/version.BuildDate=$(BUILD_TIMESTAMP)' \
-X '$(GO_MODULE_NAME)/pkg/version.Tag=$(BUILD_TAG)'

export LD_OPTS=-ldflags "-a -s -w -extldflags '-static' $(LD_OPTS_VARS)" \
	-trimpath -tags netgo

.PHONY: all
all: build test

clean-debian:
	@$(RM) -r debian/crowdsec-firewall-bouncer-iptables
	@$(RM) -r debian/crowdsec-firewall-bouncer-nftables
	@$(RM) -r debian/files
	@$(RM) -r debian/.debhelper
	@$(RM) -r debian/*.substvars
	@$(RM) -r debian/*-stamp

# Remove everything including all platform binaries and tarballs
.PHONY: clean
clean: clean-release-dir clean-debian
	@$(RM) $(BINARY_NAME)
	@$(RM) $(TARBALL_NAME)
	@$(RM) -r $(BINARY_NAME)-*	# platform binary name and leftover release dir
	@$(RM) $(BINARY_NAME)-*.tgz	# platform release file

#
# Build binaries
#

.PHONY: binary
binary: goversion
	$(GOBUILD) $(LD_OPTS) $(BUILD_VENDOR_FLAGS) -o $(BINARY_NAME)

.PHONY: build
build: goversion clean binary

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

# Called during release, to reuse the directory for other platforms
.PHONY: clean-release-dir
clean-release-dir:
	@$(RM) -r $(RELDIR)

.PHONY: tarball
tarball: binary
	@if [ -z $(BUILD_VERSION) ]; then BUILD_VERSION="local" ; fi
	@if [ -d $(RELDIR) ]; then echo "$(RELDIR) already exists, please run 'make clean' and retry" ;  exit 1 ; fi
	@echo Building Release to dir $(RELDIR)
	@mkdir $(RELDIR)/
	@cp $(BINARY_NAME) $(RELDIR)/
	@cp -R ./config $(RELDIR)/
	@cp ./scripts/install.sh $(RELDIR)/
	@cp ./scripts/uninstall.sh $(RELDIR)/
	@cp ./scripts/upgrade.sh $(RELDIR)/
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
platform-all: goversion clean
	python3 .github/release.py run-build $(BINARY_NAME)

# Check if go is the right version
include mk/goversion.mk
