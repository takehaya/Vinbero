# Vinbero interop containerlab labs.
#
# An interop test library: Vinbero peered against an independent
# third-party router (FRR today, SR Linux / others per scenario). Each
# scenario lives under scenarios/<name>/ and is driven through SCENARIO.
#
# Typical flow:
#   make build                    # build the shared container images
#   make deploy                   # bring the default scenario up
#   make test                     # run the scenario's assertions
#   make destroy                  # tear it down
#   make all                      # build + deploy + test + destroy
#
# Pick a scenario explicitly:
#   make all SCENARIO=l3vpn-2site
#
# `make scenarios` lists every available scenario.

# Repo root: image builds need it as the Docker build context (the
# vinberod image is a multi-stage build of the whole Go module).
ROOT_DIR := $(shell git rev-parse --show-toplevel)

# Directory of THIS Makefile (examples/interop-clab/).
LAB_DIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

# Scenario selection. Each scenario is scenarios/<SCENARIO>/.
SCENARIO ?= l3vpn-2site
SCENARIO_DIR := $(LAB_DIR)/scenarios/$(SCENARIO)
TOPO         := $(SCENARIO_DIR)/clab.yml

# Shared container images (built once, reused by every scenario).
VINBERO_IMAGE ?= vinbero-interop:latest
FRR_IMAGE     ?= frr-interop:10.2.1

.PHONY: all build build-vinbero build-frr deploy destroy reload test \
        logs status scenarios

all: build deploy test destroy

build: build-vinbero build-frr

# Vinbero runtime image. Build context = repo root; the BPF objects are
# committed + embedded, so no `make bpf-gen` is needed.
build-vinbero:
	docker build \
		-t $(VINBERO_IMAGE) \
		-f $(LAB_DIR)/images/vinbero/Dockerfile \
		$(ROOT_DIR)

# FRR remote PE image (pinned 10.2.x base, see images/frr/Dockerfile).
build-frr:
	docker build \
		-t $(FRR_IMAGE) \
		-f $(LAB_DIR)/images/frr/Dockerfile \
		$(LAB_DIR)/images/frr

deploy:
	sudo containerlab -t $(TOPO) deploy

destroy:
	sudo containerlab -t $(TOPO) destroy -c

reload: destroy deploy

# Run the selected scenario's assertions against a running lab.
test:
	sudo bash $(SCENARIO_DIR)/test.sh

# List the available scenarios.
scenarios:
	@echo "Available scenarios (scenarios/<name>/):"
	@for d in $(LAB_DIR)/scenarios/*/; do \
		echo "  - $$(basename $$d)"; \
	done
	@echo ""
	@echo "Current: SCENARIO=$(SCENARIO)"

# Quick state dump for debugging the selected scenario.
status:
	@echo "=== FRR BGP summary ==="
	-docker exec clab-$(SCENARIO)-pe-osaka vtysh -c "show bgp summary"
	@echo ""
	@echo "=== FRR VPNv4 table ==="
	-docker exec clab-$(SCENARIO)-pe-osaka vtysh -c "show bgp ipv4 vpn"
	@echo ""
	@echo "=== Vinbero headend-v4 entries ==="
	-docker exec clab-$(SCENARIO)-pe-tokyo vbctl headend-v4 list

logs:
	@echo "=== vinberod log ==="
	-docker exec clab-$(SCENARIO)-pe-tokyo cat /var/log/vinberod.log
	@echo ""
	@echo "=== FRR log ==="
	-docker exec clab-$(SCENARIO)-pe-osaka cat /var/log/frr/frr.log
