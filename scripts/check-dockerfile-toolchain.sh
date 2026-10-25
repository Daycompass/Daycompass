#!/usr/bin/env bash
# Fails if the Rust image in the Dockerfile and `channel` in
# rust-toolchain.toml name different compiler versions.
#
# rust-toolchain.toml is not copied into the container build (see
# .dockerignore), so the image tag alone decides which compiler builds
# the release binary. A Dependabot bump of one without the other would
# otherwise ship a binary from a compiler CI never ran the tests with.
#
# Usage: scripts/check-dockerfile-toolchain.sh   (from the repository root)

set -euo pipefail

channel=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
image=$(sed -n 's|^FROM docker\.io/library/rust:\([0-9][0-9.]*\)-.* AS build$|\1|p' Dockerfile)

if [ -z "$channel" ] || [ -z "$image" ]; then
    echo "could not read the toolchain (got '$channel') or the build image tag (got '$image')" >&2
    exit 1
fi

if [ "$channel" != "$image" ]; then
    echo "rust-toolchain.toml says $channel, the Dockerfile builds with rust:$image" >&2
    exit 1
fi

echo "toolchain and build image agree: $channel"
