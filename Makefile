# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get

# Current versioning information from env
BUILD_VERSION?="$(shell git describe --tags)"
BUILD_TIMESTAMP=$(shell date +%F"_"%T)
BUILD_TAG?=$(shell git rev-parse HEAD)

LD_OPTS_VARS=\
-X github.com/crowdsecurity/cs-firewall-bouncer/pkg/version.Version=$(BUILD_VERSION) \
-X github.com/crowdsecurity/cs-firewall-bouncer/pkg/version.BuildDate=$(BUILD_TIMESTAMP) \
-X github.com/crowdsecurity/cs-firewall-bouncer/pkg/version.Tag=$(BUILD_TAG)

ifdef BUILD_STATIC
	export LD_OPTS=-ldflags "-a -s -w -extldflags '-static' $(LD_OPTS_VARS)" -tags netgo
else
	export LD_OPTS=-ldflags "-a -s -w $(LD_OPTS_VARS)"
endif

PREFIX?="/"
BINARY_NAME=crowdsec-firewall-bouncer

RELDIR = "crowdsec-firewall-bouncer-${BUILD_VERSION}"

PYTHON=python3
PIP=pip

all: clean build

.PHONY: lint
lint:
	golangci-lint run

build: goversion clean
	$(GOBUILD) $(LD_OPTS) $(BUILD_VENDOR_FLAGS) -o $(BINARY_NAME)

.PHONY: test
test:
	@$(GOTEST) $(LD_OPTS) ./...

clean-debian:
	@$(RM) -r debian/crowdsec-firewall-bouncer-iptables
	@$(RM) -r debian/crowdsec-firewall-bouncer-nftables
	@$(RM) -r debian/files
	@$(RM) -r debian/*.substvars
	@$(RM) -r debian/*.debhelper
	@$(RM) -r debian/*-stamp

clean: clean-debian
	@$(RM) $(BINARY_NAME)
	@$(RM) -r ${RELDIR}
	@$(RM) crowdsec-firewall-bouncer.tgz
	@$(RM) -r test/venv

.PHONY: func-tests
func-tests: build
	( \
	$(PYTHON) -m venv test/venv ; \
	tests/venv/bin/$(PIP) install -r test/requirements.txt ; \
	sudo test/venv/bin/$(PYTHON) -B -m unittest -v ; \
	)

.PHONY: release
release: build
	@if [ -z ${BUILD_VERSION} ] ; then BUILD_VERSION="local" ; fi
	@if [ -d $(RELDIR) ]; then echo "$(RELDIR) already exists, clean" ;  exit 1 ; fi
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
	@tar cvzf crowdsec-firewall-bouncer.tgz $(RELDIR)

include mk/goversion.mk
