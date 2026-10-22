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

cargo build --release --locked -p sluse-endpoint
npm --prefix ui/console ci
npm --prefix ui/console run build

stage=$(mktemp -d)
mkdir -p "$stage/sluse/bin" "$stage/sluse/ui/console"
cp target/release/sluse-endpoint "$stage/sluse/bin/"
cp ui/console/index.html ui/console/style.css "$stage/sluse/ui/console/"
cp -r ui/console/look "$stage/sluse/ui/console/look"
cp -r ui/console/dist "$stage/sluse/ui/console/dist"
cp -r packaging/box/kiosk "$stage/sluse/kiosk"
# Which tree it came from, as the Windows package's VERSION.txt says it.
echo "$(git rev-parse --short HEAD)$(git diff --quiet || echo -dirty)" > "$stage/sluse/COMMIT"

mkdir -p "$out"
tar czf "$out/sluse-box-linux.tar.gz" -C "$stage" sluse
rm -rf "$stage"
echo "$out/sluse-box-linux.tar.gz"
