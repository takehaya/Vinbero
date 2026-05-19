# Shared Vinbero runtime image for the interop-clab scenarios.
#
# This is NOT a release artifact: it stays decoupled from the goreleaser
# pipeline on purpose. It only builds the two binaries the lab needs and
# drops them onto a small Debian base.
#
# The BPF objects are committed under pkg/bpf/ and embedded via go:embed,
# so `make bpf-gen` is NOT needed -- a plain `go build` is enough.
#
# The container runs privileged in the lab (XDP attach + BPF FS), so the
# runtime base just needs iproute2 / ethtool for interface setup and a
# shell for the start script.

# --- build stage -----------------------------------------------------------
FROM golang:1.25-bookworm AS build

WORKDIR /src

# Prime the module cache first so source-only edits do not re-download.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO is not needed: the cilium/ebpf loader is pure Go and the BPF
# objects are embedded. Static binaries keep the runtime base minimal.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/vinberod ./cmd/vinberod \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/vinbero  ./cmd/vinbero

# --- runtime stage ---------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# iproute2 / ethtool: interface bring-up and offload tweaks in start.sh.
# tcpdump / iputils-ping: data-plane debugging (the optional stretch goal).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        iproute2 ethtool tcpdump iputils-ping ca-certificates \
        procps bash \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/vinberod /usr/local/bin/vinberod
COPY --from=build /out/vinbero  /usr/local/bin/vinbero

# `vbctl` is the name the docs/CLI use for the client binary.
RUN ln -s /usr/local/bin/vinbero /usr/local/bin/vbctl

# containerlab drives the lifecycle through the topology `exec:` hooks,
# so the default command just keeps the container alive.
CMD ["sleep", "infinity"]
