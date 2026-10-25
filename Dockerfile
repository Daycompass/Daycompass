# Daycompass server: one binary, one container.
#
# Build:  podman build -t daycompass .     (or `docker build`)
# Run:    see README.md, "Running in a container".
#
# Both base images are pinned by digest, so a rebuild uses exactly the
# same bases until Dependabot proposes newer ones (.github/dependabot.yml).

# --- build ------------------------------------------------------------
#
# The tag must match `channel` in rust-toolchain.toml; that file is not
# copied into the build (see .dockerignore), so this tag alone decides
# the compiler. Debian trixie, the same release as the runtime image
# below, so the binary links against the glibc it will run with.
FROM docker.io/library/rust:1.99.0-slim-trixie@sha256:2752b332db73fdbb7dc576f06c82ed1f312005784ef913d7e04a28f5f55dc581 AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# `--locked`: the lockfile is the dependency set CI and `cargo deny`
# checked, never a fresh resolution. SQLite is compiled from source
# (`sqlite-bundled`), which is why the C compiler in this image matters.
RUN cargo build --release --locked -p daycompass-server \
    && cp target/release/daycompass-server /daycompass-server

# The data directory, owned by the runtime user (uid 65532, distroless
# `nonroot`). The server chmods it to 0700 at startup and has to own it
# to do that. Created here because the runtime image has no shell.
RUN mkdir /data && chown 65532:65532 /data

# --- runtime ----------------------------------------------------------
#
# Distroless `cc`: glibc and libgcc, nothing else - no shell, no package
# manager, nothing to log in with. `nonroot` runs as uid 65532.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:3ee00291cf386ec52a552e6a858d555debd74776eb4bfa53fa3df2cd6677515e

LABEL org.opencontainers.image.title="daycompass-server" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

COPY --from=build /daycompass-server /usr/local/bin/daycompass-server
COPY --from=build --chown=65532:65532 /data /data

# Defaults for a container only; every one can be overridden with `-e`.
# Binding beyond loopback makes DAYCOMPASS_PUBLIC_URL mandatory, so a
# container started without it refuses to start rather than guessing
# the origin its Origin checks compare against.
ENV DAYCOMPASS_BIND_ADDR=0.0.0.0:8080 \
    DAYCOMPASS_DATA_DIR=/data

# Declared so a container started without `-v` still keeps its database
# in a volume rather than in the container's writable layer.
VOLUME ["/data"]
EXPOSE 8080
USER 65532:65532

# The binary is PID 1 and handles SIGTERM itself (graceful shutdown).
# No HEALTHCHECK: the image has nothing to run one with. Probe
# `GET /healthz` from the orchestrator instead.
ENTRYPOINT ["/usr/local/bin/daycompass-server"]
