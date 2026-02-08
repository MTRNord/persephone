# syntax=docker/dockerfile:1.4
ARG TARGETARCH
ARG TARGETPLATFORM
ARG BUILDPLATFORM

FROM fedora:42 AS builder
ARG TARGETARCH
ARG TARGETPLATFORM
ARG BUILDPLATFORM

WORKDIR /build

# Install build dependencies. When building for arm64 (cross-compiling from amd64),
# install an aarch64 cross-toolchain and glibc/sysroot packages. For native amd64 builds,
# install the normal toolchain.
RUN dnf -y update && \
    if [ "$TARGETARCH" = "arm64" ]; then \
    dnf -y copr enable lantw44/aarch64-linux-gnu-toolchain || true && \
    dnf -y install \
    libevent-devel libicu-devel libasan libubsan libsodium-devel libpq-devel \
    jsoncpp-devel hiredis-devel ldns ldns-devel yaml-cpp yaml-cpp-devel \
    uuid-devel zlib-devel clang-tools-extra ninja-build cmake git clang \
    gcc-aarch64-linux-gnu gcc-c++-aarch64-linux-gnu aarch64-linux-gnu-glibc; \
    else \
    dnf -y install \
    libevent-devel libicu-devel libasan libubsan libsodium-devel libpq-devel \
    jsoncpp-devel hiredis-devel ldns ldns-devel yaml-cpp yaml-cpp-devel \
    uuid-devel zlib-devel clang-tools-extra ninja-build cmake git clang \
    gcc gcc-c++ make; \
    fi && \
    dnf clean all

# Create the cmake toolchain file for arm64 cross-compilation (only when TARGETARCH=arm64).
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

# Build drogon. Use the toolchain file if cross-compiling to arm64.
RUN cd /tmp && git clone https://github.com/drogonframework/drogon && \
    cd drogon && git submodule update --init && mkdir -p build && cd build && \
    if [ "$TARGETARCH" = "arm64" ]; then \
    cmake -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_POSTGRESQL=ON -DBUILD_REDIS=OFF -DBUILD_SQLITE=OFF -DBUILD_MYSQL=OFF \
    -DBUILD_ORM=ON -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_TOOLCHAIN_FILE=/usr/share/cmake/Modules/Platform/Linux-aarch64.cmake .. ; \
    else \
    cmake -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_POSTGRESQL=ON -DBUILD_REDIS=OFF -DBUILD_SQLITE=OFF -DBUILD_MYSQL=OFF \
    -DBUILD_ORM=ON -DBUILD_SHARED_LIBS=ON .. ; \
    fi && \
    make -j"$(nproc)" && make install

# Copy repository and build persephone. Use the same toolchain file when cross-compiling.
COPY . .

RUN if [ "$TARGETARCH" = "arm64" ]; then \
    cmake -B builddir -S . -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/persephone \
    -DCMAKE_TOOLCHAIN_FILE=/usr/share/cmake/Modules/Platform/Linux-aarch64.cmake ; \
    else \
    cmake -B builddir -S . -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/persephone ; \
    fi && \
    cmake --build builddir --config Release -- -j"$(nproc)" && \
    cmake --install builddir --config Release

# Final runtime image (Buildx will assemble the correct multi-arch manifest).
FROM fedora:42

RUN dnf -y install libasan libubsan libsodium libpq jsoncpp hiredis ldns yaml-cpp uuid zlib && \
    dnf clean all

COPY --from=builder /persephone /persephone

WORKDIR /persephone
EXPOSE 8008 8448

CMD ["./persephone"]
