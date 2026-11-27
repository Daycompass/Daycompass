# Daycompass server: one binary, one container.
#
# Build:  podman build -t daycompass .     (or `docker build`)
#         Add `--build-arg DAYCOMPASS_BUILD_COMMIT=$(git rev-parse --short HEAD)`
#         to show the commit next to the version on the dashboard.
# Run:    see docs/guide.md, "Running in a container".
#
# Both base images are pinned by digest, so a rebuild uses exactly the
# same bases until Dependabot proposes newer ones (.github/dependabot.yml).

# --- build ------------------------------------------------------------
#
# The tag must match `channel` in rust-toolchain.toml; that file is not
# copied into the build (see .dockerignore), so this tag alone decides
# the compiler. CI enforces the match (scripts/check-dockerfile-toolchain.sh)
# and builds and starts this image on every pull request. Debian trixie, the same release as the runtime image
# below, so the binary links against the glibc it will run with.
FROM docker.io/library/rust:1.99.1-slim-trixie@sha256:f6c4a35d21dbb3c89d7a8d056c193e94fc09037f2b58dd858b09c39a47dd02d7 AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# The commit to show next to the version (see `crate::build`). Optional:
# `.git` is not in the build context, so it has to be passed in. A build
# argument is visible to the `RUN` below, and only at compile time - it
# is not in the runtime image's environment.
ARG DAYCOMPASS_BUILD_COMMIT=

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
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:29ee70762214fe8190cea04ef1c0a84a8365879e047ce8f911ae5a5ab2355fa2

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
