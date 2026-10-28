#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
runner_args=()
case "${1:-}" in
  '') ;;
  --with-private)
    for required in captures/rf-startup.pcapng captures/rf-boss-baseline.pcapng captures/rf-empty-buddy.pcapng fixtures/lobby-boss-v2.bin; do
      [[ -f "private/$required" ]] || { printf 'Missing required private fixture: %s\n' "$required" >&2; exit 2; }
    done
    runner_args=(--private-root "$repo_root/private") ;;
  *) printf 'Usage: scripts/check.sh [--with-private]\n' >&2; exit 2 ;;
esac
[[ $# -le 1 ]] || { printf 'Too many arguments\n' >&2; exit 2; }
sdk_root="${RF_DOTNET_ROOT:-$repo_root/.dotnet}"
if [[ -x "$sdk_root/dotnet" ]]; then
  dotnet_command="$sdk_root/dotnet"
else
  dotnet_command="$(command -v dotnet || true)"
fi
[[ -n "$dotnet_command" ]] || { printf 'Run scripts/install-dotnet.sh first.\n' >&2; exit 1; }
export DOTNET_CLI_HOME="${DOTNET_CLI_HOME:-$repo_root/.dotnet-home}"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export PYTHONDONTWRITEBYTECODE=1
python3 -m unittest discover -s work/protocol-lab -p 'test_*.py' -v
node work/protocol-lab/test_trace_sanitizer.js
"$dotnet_command" build tools/Preservation.Checks --configuration Release --nologo
"$dotnet_command" run --project tools/Preservation.Checks --configuration Release --no-build -- "${runner_args[@]}"
python3 scripts/smoke_backend.py
