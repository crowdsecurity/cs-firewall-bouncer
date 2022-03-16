
# CROWDSEC_DIR ?= "~/src/crowdsec"

define ENV :=
export CROWDSEC_DIR=$(CROWDSEC_DIR)
endef

require-%:
	@ if [ "${${*}}" = "" ]; then \
		echo "Environment variable $* not set"; \
		exit 1; \
	fi

bats-all: bats-clean bats-build bats-test

# Source this to run the scripts outside of the Makefile
bats-environment: require-CROWDSEC_DIR
	$(file >$(CURDIR)/tests/.environment.sh,$(ENV))

bats-clean: require-CROWDSEC_DIR
	@${MAKE} -C $(CROWDSEC_DIR) bats-clean

bats-build: require-CROWDSEC_DIR
	@${MAKE} -C $(CROWDSEC_DIR) bats-build

bats-test: require-CROWDSEC_DIR
	@$(CURDIR)/tests/bats/run-tests

# Static checks for the test scripts.
# Not failproof but they can catch bugs and improve learning of sh/bash
bats-lint:
	@shellcheck --version >/dev/null 2>&1 || (echo "ERROR: shellcheck is required."; exit 1)
	@shellcheck -x $(CURDIR)/tests/bats/*.bats

