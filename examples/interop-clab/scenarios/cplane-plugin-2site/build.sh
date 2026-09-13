#!/bin/bash
# Build the artifacts this scenario bind-mounts but does not commit.
#
# The eBPF half of the custom behavior is compiled rather than committed,
# the way every other eBPF plugin example under sdk/examples is: the object
# depends on the SDK headers it was built against, and a stale committed
# one fails the MapReplacements compatibility check at PluginRegister with
# nothing saying why. The WebAssembly half is committed, because building
# it needs TinyGo and the lab should not.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"

make -C "$root/sdk/examples/plugin-custom-behavior"
