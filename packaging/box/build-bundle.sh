#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 SerenIT ApS and Prompted EV
#
# The box's bundle: the endpoint, the console, and the units that run them
# (slices 1 and 2). Built on Linux: in CI's guest job, or on the development
# guest. It unpacks to `sluse/`, and `sudo bash sluse/kiosk/install.sh <user>`
# puts it into a box. Slice 3's image build carries the same bundle.
#
#   packaging/box/build-bundle.sh            # writes dist/sluse-box-linux.tar.gz
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"
out=${1:-dist}

# The endpoint, and the console drawn without a web stack (D-079).
cargo build --release --locked -p sluse-endpoint -p sluse-console

stage=$(mktemp -d)
mkdir -p "$stage/sluse/bin"
cp target/release/sluse-endpoint "$stage/sluse/bin/"
cp target/release/sluse-console "$stage/sluse/bin/"
cp -r packaging/box/kiosk "$stage/sluse/kiosk"
# Which tree it came from, as the Windows package's VERSION.txt says it.
echo "$(git rev-parse --short HEAD)$(git diff --quiet || echo -dirty)" > "$stage/sluse/COMMIT"

mkdir -p "$out"
tar czf "$out/sluse-box-linux.tar.gz" -C "$stage" sluse
rm -rf "$stage"
echo "$out/sluse-box-linux.tar.gz"
