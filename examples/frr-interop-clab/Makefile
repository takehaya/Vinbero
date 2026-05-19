# FRR <-> Vinbero BGP SRv6 interop lab (containerlab).
#
# Typical flow:
#   make build      # build both container images
#   make deploy     # bring the 3-node topology up
#   make test       # assert bidirectional SRv6 L3VPN route exchange
#   make destroy    # tear the lab down
#
# `make all` chains build + deploy + test + destroy.

# Repo root: image builds need it as the Docker build context (the
# vinberod image is a multi-stage build of the whole Go module).
ROOT_DIR := $(shell git rev-parse --show-toplevel)

VINBERO_IMAGE ?= vinbero-interop:latest
FRR_IMAGE     ?= frr-interop:10.2.1
TOPO          ?= clab.yml

.PHONY: all build build-vinbero build-frr deploy destroy reload test logs status

all: build deploy test destroy

build: build-vinbero build-frr

# Vinbero runtime image. Build context = repo root; the BPF objects are
# committed + embedded, so no `make bpf-gen` is needed.
build-vinbero:
	docker build \
		-t $(VINBERO_IMAGE) \
		-f $(ROOT_DIR)/examples/frr-interop-clab/Dockerfile \
		$(ROOT_DIR)

# FRR remote PE image (pinned 10.2.x base, see frr/Dockerfile).
build-frr:
	docker build \
		-t $(FRR_IMAGE) \
		-f frr/Dockerfile \
		frr/

deploy:
	sudo containerlab -t $(TOPO) deploy

destroy:
	sudo containerlab -t $(TOPO) destroy -c

reload: destroy deploy

# SRv6 L3VPN interop assertions: bidirectional route exchange (control
# plane) plus a bidirectional ping over the L3VPN (data plane).
test:
	sudo bash test.sh

# Quick state dump for debugging.
status:
	@echo "=== FRR BGP summary ==="
	-docker exec clab-frr-interop-frr vtysh -c "show bgp summary"
	@echo ""
	@echo "=== FRR VPNv4 table ==="
	-docker exec clab-frr-interop-frr vtysh -c "show bgp ipv4 vpn"
	@echo ""
	@echo "=== Vinbero headend-v4 entries ==="
	-docker exec clab-frr-interop-vinbero vbctl headend-v4 list

logs:
	@echo "=== vinberod log ==="
	-docker exec clab-frr-interop-vinbero cat /var/log/vinberod.log
	@echo ""
	@echo "=== FRR log ==="
	-docker exec clab-frr-interop-frr cat /var/log/frr/frr.log
