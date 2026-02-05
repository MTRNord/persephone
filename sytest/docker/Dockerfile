# Dockerfile for running Sytest against Persephone
# Based on the official sytest Docker image which has sytest pre-installed

FROM matrixdotorg/sytest:testing

# Install C++ build dependencies for Persephone
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build tools
    build-essential \
    pkg-config \
    cmake \
    ninja-build \
    git \
    # Compiler toolchain
    clang-21 \
    lld-21 \
    # Persephone dependencies
    libpq-dev \
    libsodium-dev \
    libyaml-cpp-dev \
    libldns-dev \
    libjsoncpp-dev \
    nlohmann-json3-dev \
    uuid-dev \
    zlib1g-dev \
    libssl-dev \
    libevent-dev \
    libicu-dev \
    # PostgreSQL
    postgresql \
    postgresql-contrib \
    # Additional perl deps
    libdbi-perl \
    libdbd-pg-perl \
    && rm -rf /var/lib/apt/lists/*

# Fix jsoncpp include path (debian vs fedora difference)
RUN if [ -d /usr/include/jsoncpp/json ] && [ ! -d /usr/include/json ]; then \
        ln -s /usr/include/jsoncpp/json /usr/include/json; \
    fi

# Build and install drogon framework
RUN cd /tmp && \
    git clone --depth 1 https://github.com/drogonframework/drogon && \
    cd drogon && \
    git submodule update --init && \
    mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DBUILD_POSTGRESQL=ON \
          -DBUILD_REDIS=OFF \
          -DBUILD_SQLITE=OFF \
          -DBUILD_MYSQL=OFF \
          -DBUILD_ORM=ON \
          -DBUILD_SHARED_LIBS=ON \
          .. && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    rm -rf /tmp/drogon

# Configure PostgreSQL for trust authentication on localhost
RUN find /etc/postgresql -name pg_hba.conf -exec sed -i 's/peer/trust/g' {} \; && \
    find /etc/postgresql -name pg_hba.conf -exec sed -i 's/scram-sha-256/trust/g' {} \; && \
    find /etc/postgresql -name pg_hba.conf -exec sed -i 's/md5/trust/g' {} \; && \
    find /etc/postgresql -name postgresql.conf -exec sed -i 's/max_connections = 100/max_connections = 500/g' {} \;

# Create directories
RUN mkdir -p /src /build /logs /work /persephone

# Copy Persephone source
COPY . /src

# Copy sytest plugin files into sytest (sytest is at /sytest in the base image)
COPY sytest/lib/SyTest/Homeserver/Persephone.pm /sytest/lib/SyTest/Homeserver/
COPY sytest/lib/SyTest/HomeserverFactory/Persephone.pm /sytest/lib/SyTest/HomeserverFactory/

# Build Persephone
RUN cd /src && \
    CC=clang-21 CXX=clang++-21 cmake -B /build -S . \
        -DCMAKE_BUILD_TYPE=Release \
        -DDISABLE_TESTS=ON \
        -DCMAKE_INSTALL_PREFIX=/persephone \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld" \
        -DCMAKE_SHARED_LINKER_FLAGS="-fuse-ld=lld" && \
    cmake --build /build -j$(nproc) && \
    cmake --install /build

# Copy runner script and config files
COPY sytest/scripts/persephone_sytest.sh /sytest/scripts/
COPY sytest/whitelist.txt /sytest/persephone_whitelist.txt
COPY sytest/blacklist.txt /sytest/persephone_blacklist.txt
RUN chmod +x /sytest/scripts/persephone_sytest.sh

# Set up environment
ENV SYTEST_PLUGINS=/sytest/lib
ENV PERSEPHONE_BINARY=/persephone/bin/persephone

WORKDIR /sytest

ENTRYPOINT ["/bin/bash", "/sytest/scripts/persephone_sytest.sh"]
