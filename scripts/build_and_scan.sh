#!/usr/bin/env bash
# Build the three images from the working tree, smoke-test each, and write a
# Trivy JSON report per image: <outdir>/{core,hf,deep}.json.
#
# This never judges the result — `scripts/trivy_gate.py report` does that. An
# image that fails to build or boot simply gets no report, which the gate
# counts as not clean. The exit status is only about the scan *machinery*:
# 0 = every buildable image was scanned, 2 = Trivy itself could not run (DB
# download, registry outage), which must fail the job rather than be mistaken
# for "the images are vulnerable".
#
# Same severity filter as the CI and release gates: HIGH/CRITICAL, fixed only.
#
# Usage: scripts/build_and_scan.sh <tag> <outdir>
set -uo pipefail

tag=${1:?usage: build_and_scan.sh <tag> <outdir>}
out=${2:?usage: build_and_scan.sh <tag> <outdir>}
here=$(cd "$(dirname "$0")" && pwd)

mkdir -p "$out"
rm -f "$out"/*.json

scan() { # image report
  local attempt
  for attempt in 1 2 3; do
    if trivy image --quiet --format json --output "$2" \
         --severity HIGH,CRITICAL --ignore-unfixed --exit-code 0 "$1"; then
      return 0
    fi
    rm -f "$2"
    echo "trivy failed on $1 (attempt $attempt/3)" >&2
    sleep $((attempt * 15))
  done
  return 1
}

for name in core hf deep; do
  file=Dockerfile
  [ "$name" = core ] || file="Dockerfile.$name"
  image="purser-$name:$tag"

  echo "::group::build $image"
  if ! docker build -t "$image" -f "$file" .; then
    echo "::endgroup::"
    echo "::warning::$name: image failed to build"
    continue
  fi
  echo "::endgroup::"

  if ! "$here/smoke_image.sh" "$image"; then
    echo "::warning::$name: image built but did not start"
    continue
  fi

  if ! scan "$image" "$out/$name.json"; then
    echo "::error::Trivy could not scan $image"
    exit 2
  fi
done
