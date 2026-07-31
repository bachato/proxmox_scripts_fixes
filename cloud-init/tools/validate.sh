#!/bin/bash
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

python3 "$script_dir/render_profiles.py" --check
python3 "$script_dir/validate_profiles.py"
