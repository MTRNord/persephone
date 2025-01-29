# syntax=docker/dockerfile:1.4
FROM --platform=$BUILDPLATFORM fedora:41 AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG CROSS_COMPILE

# TODO: Figure out how to get an arm64 c++ stdlib to link to...
RUN dnf copr enable -y lantw44/aarch64-linux-gnu-toolchain && dnf install -y libicu-devel libasan libubsan libsodium-devel libpq-devel jsoncpp-devel hiredis-devel ldns ldns-devel yaml-cpp yaml-cpp-devel uuid-devel zlib-devel clang-tools-extra ninja-build cmake git clang gcc-aarch64-linux-gnu gcc-c++-aarch64-linux-gnu aarch64-linux-gnu-glibc

WORKDIR /build

# Create the toolchain file
RUN mkdir -p /usr/share/cmake/Modules/Platform && \
    echo "set(CMAKE_SYSTEM_NAME Linux)" > /usr/share/cmake/Modules/Platform/Linux-aarch64.cmake && \
    echo "set(CMAKE_SYSTEM_PROCESSOR aarch64)" >> /usr/share/cmake/Modules/Platform/Linux-aarch64.cmake && \
    echo "set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)" >> /usr/share/cmake/Modules/Platform/Linux-aarch64.cmake && \
    echo "set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)" >> /usr/share/cmake/Modules/Platform/Linux-aarch64.cmake && \
    echo "set(CMAKE_FIND_ROOT_PATH /usr/aarch64-linux-gnu /usr/local/aarch64-linux-gnu)" >> /usr/share/cmake/Modules/Platform/Linux-aarch64.cmake && \
    echo "set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)" >> /usr/share/cmake/Modules/Platform/Linux-aarch64.cmake && \
    echo "set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)" >> /usr/share/cmake/Modules/Platform/Linux-aarch64.cmake && \
    echo "set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)" >> /usr/share/cmake/Modules/Platform/Linux-aarch64.cmake


# Due to https://bugzilla.redhat.com/show_bug.cgi?id=2338878 in /usr/lib/pkgconfig/ldns.pc we need to replace `includedir=/usr/include/ldns/ldns` with `includedir=/usr/include/ldns`.
RUN sed -i 's%includedir=/usr/include/ldns/ldns%includedir=/usr/include/ldns%g' /usr/lib64/pkgconfig/ldns.pc

# Build drogon
RUN cd /tmp && git clone https://github.com/drogonframework/drogon && cd drogon && git submodule update --init && mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_POSTGRESQL=ON -DBUILD_REDIS=OFF -DBUILD_SQLITE=OFF -DBUILD_MYSQL=OFF -DBUILD_ORM=ON -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_TOOLCHAIN_FILE=/usr/share/cmake/Modules/Platform/Linux-aarch64.cmake .. && make && make install

COPY . .

# Build and install persephone
RUN cmake -B builddir -S . -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/persephone -DCMAKE_TOOLCHAIN_FILE=/usr/share/cmake/Modules/Platform/Linux-aarch64.cmake && \
    cmake --build builddir --config Release && cmake --install builddir --config Release

FROM fedora:41

RUN dnf install -y libasan libubsan libsodium libpq jsoncpp hiredis ldns yaml-cpp uuid zlib

COPY --from=builder /persephone /persephone

WORKDIR /persephone
EXPOSE 8008 8448

CMD ./persephone