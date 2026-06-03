# cf. based https://gist.github.com/thomaspoignant/5b72d579bd5f311904d973652180c705
GOCMD=go
GOTEST=$(GOCMD) test
GOVET=$(GOCMD) vet
CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
DIFF_FROM_BRANCH_NAME ?= origin/main

ENTRY_POINT_DIR=cmd
TARGETS=$(notdir $(wildcard $(ENTRY_POINT_DIR)/*))

GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
WHITE  := $(shell tput -Txterm setaf 7)
CYAN   := $(shell tput -Txterm setaf 6)
RESET  := $(shell tput -Txterm sgr0)

.PHONY: all
all: help

## Build:
.PHONY: build, make_outdir, clean
build: make_outdir build-targets ## Build your project and put the output binary in out/bin/
make_outdir:
	mkdir -p out/bin

.PHONY: $(TARGETS)
.PHONY: build-targets
build-targets: $(TARGETS) ## Build main targets
$(TARGETS):
	$(GOCMD) build -o out/bin/$@ ./cmd/$@/

.PHONY: goreleaser
goreleaser: ## build with goreleaser
	goreleaser release --snapshot --clean

clean: ## Remove build related file
	rm -fr ./out/bin

## Test:
.PHONY: test-runnable
test-runnable: ## check no panic at init()
	@for file in $(TARGETS); do \
		echo [test] $$file; \
		./out/bin/$$file -v; \
		if [ $$? -ne 0 ]; then \
			echo "Failed to run $$file"; \
			exit 1; \
		fi; \
	done

.PHONY: test
test: ## Run the tests of the project
	$(GOTEST) -v -exec sudo -race ./... $(OUTPUT_OPTIONS)

VIMTO_KERNEL ?= 6.6
.PHONY: test-bpf-load
test-bpf-load: ## Run BPF load test in QEMU VM (requires vimto + QEMU). Usage: make test-bpf-load [VIMTO_KERNEL=6.12]
	vimto -sudo -kernel :$(VIMTO_KERNEL) -- go test -v -count 1 -timeout 5m ./pkg/bpf/ -run TestBpfLoad

## Generate:
.PHONY: protobuf-gen
protobuf-gen: ## generate protobuf
	./scripts/generate-proto.sh

.PHONY: go-gen
go-gen: ## generate go code
	go generate ./...

.PHONY: bpf-gen
bpf-gen: export BPF_CLANG := $(CLANG)
bpf-gen: export BPF_CFLAGS := $(CFLAGS) $(CEXTRA_FLAGS)
bpf-gen: ## generate ebpf code and object files
	docker build --build-arg BPF_CLANG=${BPF_CLANG} --build-arg BPF_CFLAGS="${BPF_CFLAGS}" . --output ./pkg/bpf -f Dockerfile.bpf

## Lint:
.PHONY: install-lint-tools
install-lint-tools: ## install lint tools
	./scripts/install_lint_tools.sh

.PHONY: lint
lint: ## Run lefthook, fmt and lint for this project.
	lefthook run pre-commit --all-files

.PHONY: lint-ci
lint-ci: ## Run lefthook for CI
	FILES="$$(git diff --name-only $(DIFF_FROM_BRANCH_NAME) HEAD | tr '\n' ' ')"; \
	if [ -n "$$FILES" ]; then \
		lefthook run pre-commit --file $$FILES; \
	fi

.PHONY: nilaway
nilaway: ## Run nil check lint
	nilaway -fix -include-pkgs="$(PACKAGE)" \
		-test=false \
		-exclude-errors-in-files="mock_" \
		./...

## tools and pkg install:
.PHONY: install-dev-pkg
install-dev-pkg: ## install mise.toml
	mise install -y

.PHONY: install-build-tools
install-build-tools: ## install build tools
	./scripts/install_build_tools.sh

.PHONY: install-dev-tools
install-dev-tools: ## install development tools
	./scripts/install_dev_tools.sh

## SDK:
SDK_PREFIX ?= /usr/local
SDK_EXAMPLES := $(wildcard sdk/examples/*/Makefile)
SDK_ALL_DIRS := $(patsubst %/Makefile,%,$(SDK_EXAMPLES))
# Negative examples are plugins authored to violate the contract on
# purpose. They MUST be excluded from sdk-build / sdk-test (which assume
# every example passes `vbctl plugin validate`) and instead run through
# sdk-test-negative, which expects validate to fail.
SDK_NEGATIVE_DIRS := sdk/examples/plugin-counter-evil
SDK_EXAMPLE_DIRS := $(filter-out $(SDK_NEGATIVE_DIRS),$(SDK_ALL_DIRS))

.PHONY: install-sdk sdk-build sdk-test sdk-test-negative sdk-clean
install-sdk: ## Install plugin SDK headers into $(SDK_PREFIX)/include/vinbero
	install -d $(SDK_PREFIX)/include/vinbero
	install -m 644 sdk/c/include/vinbero/*.h $(SDK_PREFIX)/include/vinbero/
	install -d $(SDK_PREFIX)/include/core
	install -m 644 src/core/*.h $(SDK_PREFIX)/include/core/
	install -m 644 sdk/c/Makefile.plugin $(SDK_PREFIX)/include/vinbero/Makefile.plugin

sdk-build: ## Build every sample plugin under sdk/examples/ (positive examples only)
	@for d in $(SDK_EXAMPLE_DIRS); do \
		echo "[sdk-build] $$d"; \
		$(MAKE) -C $$d || exit 1; \
	done

sdk-test: sdk-build build-targets ## Validate every built sample plugin via the CLI
	@for d in $(SDK_EXAMPLE_DIRS); do \
		obj="$$d/plugin.o"; \
		name=$$(basename $$d | tr '-' '_'); \
		if [ ! -f "$$obj" ]; then \
			echo "[sdk-test] skip $$d (no plugin.o)"; \
			continue; \
		fi; \
		echo "[sdk-test] $$obj"; \
		./out/bin/vinbero plugin validate --prog "$$obj" --program "$$name" || exit 1; \
	done

# RO-write enforcement regression check: every plugin under
# SDK_NEGATIVE_DIRS is expected to fail `vbctl plugin validate`. If one
# of them ever passes, the validator silently regressed — fail loudly.
sdk-test-negative: build-targets ## Confirm validator rejects intentionally-bad sample plugins
	@for d in $(SDK_NEGATIVE_DIRS); do \
		echo "[sdk-test-negative] build $$d"; \
		$(MAKE) -C $$d || exit 1; \
		obj="$$d/plugin.o"; \
		name=$$(basename $$d | tr '-' '_'); \
		echo "[sdk-test-negative] expect-reject $$obj"; \
		if ./out/bin/vinbero plugin validate --prog "$$obj" --program "$$name" >/dev/null 2>&1; then \
			echo "FAIL: $$obj passed validate but should be rejected"; \
			exit 1; \
		else \
			echo "OK: $$obj correctly rejected"; \
		fi; \
	done

sdk-clean: ## Clean every sample plugin under sdk/examples/ (positive + negative)
	@for d in $(SDK_ALL_DIRS); do \
		$(MAKE) -C $$d clean; \
	done

## SDK packaging:
# SDK_VERSION follows the host repo's git description so a local tarball
# built from a tagged commit lines up with the goreleaser-generated one.
# Falls back to "dev" when git metadata is unavailable (CI shallow clones).
SDK_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
SDK_STAGE := out/sdk-stage
SDK_TARBALL := out/vinbero-sdk-$(SDK_VERSION).tar.gz

.PHONY: sdk-stage
sdk-stage: ## Stage SDK tree into $(SDK_STAGE) (shared with goreleaser)
	@./scripts/stage_sdk.sh $(SDK_STAGE)

.PHONY: sdk-archive
sdk-archive: sdk-stage ## Build SDK tarball into out/
	@cd $(SDK_STAGE) && tar czf ../vinbero-sdk-$(SDK_VERSION).tar.gz include share
	@echo "Created: $(SDK_TARBALL)"

.PHONY: sdk-archive-verify
sdk-archive-verify: sdk-archive build ## Verify tarball end-to-end
	./scripts/sdk_archive_verify.sh $(SDK_TARBALL)

## Env:
.PHONY: remove-ebpfmap show-trace_pipe
remove-ebpfmap: ## remove all ebpf maps
	sudo rm -rf /sys/fs/bpf/*

show-trace_pipe: ## show trace_pipe
	sudo cat /sys/kernel/debug/tracing/trace_pipe

## Help:
.PHONY: show-buildtags
show-buildtags: ## Show build tags
	@grep -r 'go:build' ./ 2>/dev/null \
		| awk -e '/[\.]go:/' \
		| cut -d ' ' -f 2- \
		| sort -u

.PHONY: godoc
godoc: ## Start Go Document Sedrver
	@echo "Running godoc..."
	@echo "  - GODOC_HOST='$${GODOC_HOST:-localhost}'"
	@echo open http://$${GODOC_HOST:-localhost}:8080/pkg/
	@godoc -http $${GODOC_HOST:-localhost}:8080

.PHONY: help
help: ## Show this help.
	@echo ''
	@echo 'Usage:'
	@echo '  ${YELLOW}make${RESET} ${GREEN}<target>${RESET}'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} { \
		if (/^[a-zA-Z_-]+:.*?##.*$$/) { \
			printf "    ${YELLOW}%-30s${GREEN}%s${RESET}\n", $$1, $$2 \
		} \
		else if (/^## .*$$/) {printf "  ${CYAN}%s${RESET}\n", substr($$1,4)} \
		}' $(MAKEFILE_LIST)
