#!/bin/bash
# Compatibility entry point: build artifacts locally; run the generated script
# on Proxmox.
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$script_dir/build_template_bundle.py" "$@"
