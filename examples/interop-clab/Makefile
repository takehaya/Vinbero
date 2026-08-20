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

.PHONY: all build build-vinbero build-frr build-scenario provision deploy destroy reload test \
        logs status scenarios

all: build deploy test destroy

build: build-vinbero build-frr build-scenario

# Per-scenario artifacts that are built rather than committed -- an eBPF
# plugin object, say, which has to be compiled against the SDK headers of
# the checkout it runs with. A scenario opts in by shipping a `build.sh` at
# its root; most ship none and this is a no-op for them.
build-scenario:
	@if [ -f $(SCENARIO_DIR)/build.sh ]; then \
		echo "building $(SCENARIO) artifacts"; \
		bash $(SCENARIO_DIR)/build.sh; \
	fi

# Vinbero runtime image. Build context = repo root; the BPF objects are
# committed + embedded, so no `make bpf-gen` is needed. The gobgp fork that
# carries the draft-mpmz-bess-mup-safi-01 T1ST framing patch is pulled from
# go.mod (replace directive points at the fork's tagged module path), so no
# out-of-band build context is required.
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

# Post-deploy provisioning hook for a scenario whose node needs out-of-band
# setup after `make deploy` (for example a VM-based NOS that boots from a
# generic image and is configured over SSH). The scenario must ship a
# `provision.sh` at its root; this target errors if it is missing. Most
# scenarios need no provisioning and simply never call it. Not part of
# `build` and never runs in CI -- it needs a running lab and may pull in
# artifacts that are not part of this repo.
provision:
	@if [ ! -f $(SCENARIO_DIR)/provision.sh ]; then \
		echo "provision: $(SCENARIO_DIR)/provision.sh not found for SCENARIO=$(SCENARIO)"; exit 2; fi
	bash $(SCENARIO_DIR)/provision.sh

# `vrf` is loaded on demand: GitHub Actions runners (and some minimal
# hosts) ship CONFIG_NET_VRF=m unloaded, so `ip link add ... type vrf`
# inside each PE container would silently fail and FRR / Vinbero would
# come up without their customer VRF. Best-effort load; the local
# `make` already worked before this line.
deploy:
	@sudo modprobe vrf 2>/dev/null || true
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
