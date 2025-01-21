FROM fedora:41

RUN dnf install -y libsodium-devel libpq-devel jsoncpp-devel hiredis-devel ldns ldns-devel yaml-cpp yaml-cpp-devel uuid-devel zlib-devel clang-tools-extra ninja-build cmake git clang

WORKDIR /build

# Due to https://bugzilla.redhat.com/show_bug.cgi?id=2338878 in /usr/lib/pkgconfig/ldns.pc we need to replace `includedir=/usr/include/ldns/ldns` with `includedir=/usr/include/ldns`.
RUN sed -i 's%includedir=/usr/include/ldns/ldns%includedir=/usr/include/ldns%g' /usr/lib64/pkgconfig/ldns.pc

# Build drogon
RUN cd /tmp && git clone https://github.com/drogonframework/drogon && cd drogon && git submodule update --init && mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_POSTGRESQL=ON -DBUILD_REDIS=OFF -DBUILD_SQLITE=OFF -DBUILD_MYSQL=OFF -DBUILD_ORM=ON -DBUILD_SHARED_LIBS=ON .. && make && make install

COPY . .

# Build and install persephone
RUN cmake -B builddir -S . -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/persephone && cmake --build builddir --config Release && cmake --install builddir --config Release

WORKDIR /build/builddir
EXPOSE 8008 8448

CMD ./persephone