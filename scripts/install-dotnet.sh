#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
sdk_root="${RF_DOTNET_ROOT:-$repo_root/.dotnet}"
sdk_version=10.0.403
sdk_sha512=b7b3d8461cf98b07d2552ce9199702fa3ad010ac2671a5f8cd5136f7534e50f6855ba7bbb02b11494563f1d04156276a31cda1103b900e5eecd0d9473dc7b9c5
export DOTNET_CLI_HOME="${DOTNET_CLI_HOME:-$repo_root/.dotnet-home}"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
cd "$repo_root"
if [[ -x "$sdk_root/dotnet" ]] && [[ "$("$sdk_root/dotnet" --version)" == "$sdk_version" ]]; then
  printf 'SDK %s already available at %s\n' "$sdk_version" "$sdk_root"
  exit 0
fi
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  printf 'Install .NET SDK %s for your platform, then run scripts/check.sh.\n' "$sdk_version" >&2
  exit 1
fi
archive_path="$(mktemp "${TMPDIR:-/tmp}/rf-dotnet-sdk.XXXXXXXX.tar.gz")"
trap 'rm -f -- "$archive_path"' EXIT
curl --fail --location --show-error --retry 2 \
  "https://builds.dotnet.microsoft.com/dotnet/Sdk/$sdk_version/dotnet-sdk-$sdk_version-linux-x64.tar.gz" \
  --output "$archive_path"
printf '%s  %s\n' "$sdk_sha512" "$archive_path" | sha512sum --check --status
mkdir -p "$sdk_root"
tar -xzf "$archive_path" -C "$sdk_root"
[[ "$("$sdk_root/dotnet" --version)" == "$sdk_version" ]]
printf 'Installed checksum-verified SDK %s at %s\n' "$sdk_version" "$sdk_root"
