# syntax=docker/dockerfile:1.4
ARG TARGETARCH
ARG TARGETPLATFORM
ARG BUILDPLATFORM

FROM fedora:42 AS builder
ARG TARGETARCH
WORKDIR /build

# Keep package cache persistent across buildkit runs and enable ccache cache mount later.
# Use buildkit cache mounts so repeated builds are faster and layers are less frequently invalidated.
# Install build dependencies. Use cross-toolchain when cross-compiling to arm64.
RUN --mount=type=cache,target=/var/cache/dnf \
    --mount=type=cache,target=/var/cache/dnf/metadata \
    dnf -y update && \
    if [ "$TARGETARCH" = "arm64" ]; then \
    dnf -y copr enable lantw44/aarch64-linux-gnu-toolchain || true && \
    dnf -y install --setopt=keepcache=1 \
    libevent-devel libicu-devel libasan libubsan libsodium-devel libpq-devel \
    jsoncpp-devel hiredis-devel ldns ldns-devel yaml-cpp yaml-cpp-devel \
    uuid-devel zlib-devel clang-tools-extra ninja-build cmake git clang spdlog-devel c-ares-devel \
    gcc-aarch64-linux-gnu gcc-c++-aarch64-linux-gnu aarch64-linux-gnu-glibc ccache; \
    else \
    dnf -y install --setopt=keepcache=1 \
    libevent-devel libicu-devel libasan libubsan libsodium-devel libpq-devel \
    jsoncpp-devel hiredis-devel ldns ldns-devel yaml-cpp yaml-cpp-devel \
    uuid-devel zlib-devel clang-tools-extra ninja-build cmake git clang spdlog-devel c-ares-devel \
    gcc gcc-c++ make ccache; \
    fi

# If cross-compiling to arm64, write a simple CMake platform file that points to aarch64 compilers/sysroot.
RUN if [ "$TARGETARCH" = "arm64" ]; then \
    mkdir -p /usr/share/cmake/Modules/Platform && \
    printf '%s\n' \
    'set(CMAKE_SYSTEM_NAME Linux)' \
    'set(CMAKE_SYSTEM_PROCESSOR aarch64)' \
    'set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)' \
    'set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)' \
    '# Point CMake to the cross sysroot provided by the aarch64 glibc package' \
    'set(CMAKE_FIND_ROOT_PATH /usr/aarch64-linux-gnu /usr/local/aarch64-linux-gnu)' \
    'set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)' \
    'set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)' \
    'set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)' \
    > /usr/share/cmake/Modules/Platform/Linux-aarch64.cmake ; \
    fi

# Workaround: some distributions ship a broken ldns.pc with an include path that doesn't exist.
# This sed is best-effort (ignored on failure).
RUN sed -i 's%includedir=/usr/include/ldns/ldns%includedir=/usr/include/ldns%g' /usr/lib64/pkgconfig/ldns.pc || true

# Prepare ccache: create cache dir and set reasonable size.
# Use a buildkit cache mount so the ccache contents persist between builds (when buildx cache is used).
ENV CCACHE_DIR=/ccache
RUN --mount=type=cache,target=/ccache \
    mkdir -p "$CCACHE_DIR" && \
    ccache --max-size=2G || true

# Drogon is fetched and statically linked via CMake FetchContent during the build.
# No separate drogon build step is needed.

# Copy repository last to avoid invalidating the heavy install steps when source changes.
COPY . /build/persephone
WORKDIR /build/persephone

# Configure and build persephone using ccache. Use cache mounts for ccache and for cmake's intermediate files.
RUN --mount=type=cache,target=/ccache \
    --mount=type=cache,target=/root/.cache/cmake \
    export CCACHE_DIR=/ccache && \
    ccache --max-size=2G || true && \
    if [ "$TARGETARCH" = "arm64" ]; then \
    cmake -B builddir -S . -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/persephone \
    -DCMAKE_TOOLCHAIN_FILE=/usr/share/cmake/Modules/Platform/Linux-aarch64.cmake \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache ; \
    else \
    cmake -B builddir -S . -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/persephone \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache ; \
    fi && \
    cmake --build builddir --config Release -- -j"$(nproc)" && \
    cmake --install builddir --config Release

# Final runtime image (Buildx will assemble the correct multi-arch manifest).
FROM fedora:42 AS runtime

# Install only runtime libraries. Keep package cache for faster layers when possible.
RUN --mount=type=cache,target=/var/cache/dnf \
    dnf -y install c-ares spdlog libicu libasan libubsan libsodium libpq jsoncpp hiredis ldns yaml-cpp uuid zlib

COPY --from=builder /persephone /persephone

WORKDIR /persephone
EXPOSE 8008 8448

# Default command
CMD ["/persephone/bin/persephone"]
