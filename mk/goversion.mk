BUILD_GOVERSION = $(subst go,,$(shell go env GOVERSION))

go_major_minor = $(subst ., ,$(BUILD_GOVERSION))
GO_MAJOR_VERSION = $(word 1, $(go_major_minor))
GO_MINOR_VERSION = $(word 2, $(go_major_minor))

GO_VERSION_VALIDATION_ERR_MSG = Golang version ($(BUILD_GOVERSION)) is not supported, please use at least $(BUILD_REQUIRE_GO_MAJOR).$(BUILD_REQUIRE_GO_MINOR)

.PHONY: goversion
goversion:
	@if [ $(GO_MAJOR_VERSION) -gt $(BUILD_REQUIRE_GO_MAJOR) ]; then \
		exit 0; \
	elif [ $(GO_MAJOR_VERSION) -lt $(BUILD_REQUIRE_GO_MAJOR) ]; then \
		echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
		exit 1; \
	elif [ $(GO_MINOR_VERSION) -lt $(BUILD_REQUIRE_GO_MINOR) ] ; then \
		echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
		exit 1; \
	fi
