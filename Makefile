# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get

# Current versioning information from env
BUILD_VERSION?="$(shell git describe --tags)"
BUILD_GOVERSION="$(shell go version | cut -d " " -f3 | sed -r 's/[go]+//g')"
BUILD_TIMESTAMP=$(shell date +%F"_"%T)
BUILD_TAG?="$(shell git rev-parse HEAD)"

LD_OPTS_VARS=\
-X github.com/crowdsecurity/cs-firewall-bouncer/pkg/version.Version=$(BUILD_VERSION) \
-X github.com/crowdsecurity/cs-firewall-bouncer/pkg/version.BuildDate=$(BUILD_TIMESTAMP) \
-X github.com/crowdsecurity/cs-firewall-bouncer/pkg/version.Tag=$(BUILD_TAG) \
-X github.com/crowdsecurity/cs-firewall-bouncer/pkg/version.GoVersion=$(BUILD_GOVERSION)

ifdef BUILD_STATIC
	export LD_OPTS=-ldflags "-a -v -s -w -extldflags '-static' $(LD_OPTS_VARS)" -tags netgo
else
	export LD_OPTS=-ldflags "-a -v -s -w $(LD_OPTS_VARS)"
endif

PREFIX?="/"
BINARY_NAME=crowdsec-firewall-bouncer

#Golang version info
GO_MAJOR_VERSION = $(shell go version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f1)
GO_MINOR_VERSION = $(shell go version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f2)
MINIMUM_SUPPORTED_GO_MAJOR_VERSION = 1
MINIMUM_SUPPORTED_GO_MINOR_VERSION = 13
GO_VERSION_VALIDATION_ERR_MSG = Golang version ($(BUILD_GOVERSION)) is not supported, please use at least $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION).$(MINIMUM_SUPPORTED_GO_MINOR_VERSION)

RELDIR = "crowdsec-firewall-bouncer-${BUILD_VERSION}"

PYTHON=python3
PIP=pip

all: clean build

goversion:
	@if [ $(GO_MAJOR_VERSION) -gt $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION) ]; then \
		exit 0 ;\
	elif [ $(GO_MAJOR_VERSION) -lt $(MINIMUM_SUPPORTED_GO_MAJOR_VERSION) ]; then \
		echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
		exit 1; \
	elif [ $(GO_MINOR_VERSION) -lt $(MINIMUM_SUPPORTED_GO_MINOR_VERSION) ] ; then \
		echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
		exit 1; \
	fi


.PHONY: lint
lint:
	golangci-lint run

build: goversion clean
	$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME)

test:
	@$(GOTEST) $(LD_OPTS) ./...

clean:
	@$(RM) $(BINARY_NAME)
	@$(RM) -r ${RELDIR}
	@$(RM) crowdsec-firewall-bouncer.tgz
	@$(RM) -r tests/venv

.PHONY: func-tests
func-tests: build
	( \
	$(PYTHON) -m venv tests/venv ; \
	tests/venv/bin/$(PIP) install -r tests/requirements.txt ; \
	sudo tests/venv/bin/$(PYTHON) -B -m unittest -v ; \
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
