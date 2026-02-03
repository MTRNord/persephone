FROM debian:forky
RUN apt-get update && apt-get install -y libevent-dev clang-21 python3 python3-pip postgresql pkg-config cmake nlohmann-json3-dev libpq-dev libsodium23 libsodium-dev libjsoncpp-dev uuid-dev zlib1g-dev openssl libssl-dev git lsb-release wget gnupg libyaml-cpp-dev libldns-dev && apt-get upgrade -y
# jsoncpp is a bit weird on ubuntu vs fedora
RUN ln -s /usr/include/jsoncpp/json/ /usr/include/json
WORKDIR /build

# No password when connecting over localhost
RUN cat /etc/postgresql/17/main/pg_hba.conf && \
    sed -i "s%127.0.0.1/32            scram-sha-256%127.0.0.1/32            trust%g" /etc/postgresql/17/main/pg_hba.conf && \
    sed -i "s%::1/128                 scram-sha-256%::1/128                 trust%g" /etc/postgresql/17/main/pg_hba.conf && \
    # Bump up max conns for moar concurrency
    sed -i 's/max_connections = 100/max_connections = 2000/g' /etc/postgresql/17/main/postgresql.conf

# This entry script starts postgres, waits for it to be up then starts persephone
# psql -U postgres -h localhost --no-password -c \"ALTER USER postgres PASSWORD 'testing';\" \n\
RUN echo "\
#!/bin/bash -eu \n\
pg_lsclusters \n\
pg_ctlcluster 17 main start \n\
 \n\
until pg_isready \n\
do \n\
  echo \"Waiting for postgres\"; \n\
  sleep 1; \n\
done \n\
" > run_postgres.sh && chmod +x run_postgres.sh

# we will dump the binaries and config file to this location to ensure any local untracked files
# that come from the COPY . . file don't contaminate the build
RUN mkdir /persephone

COPY . .
# Install drogon
RUN cd /tmp && git clone https://github.com/drogonframework/drogon && cd drogon && git submodule update --init && mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_POSTGRESQL=ON -DBUILD_REDIS=OFF -DBUILD_SQLITE=OFF -DBUILD_MYSQL=OFF -DBUILD_ORM=ON -DBUILD_SHARED_LIBS=ON .. && make && make install && ln -s /usr/local/lib/libdrogon.so.1 /usr/lib/libdrogon.so.1 && ln -s /usr/local/lib/libtrantor.so.1 /usr/lib/libtrantor.so.1
RUN pip3 install --break-system-packages ninja

# Build and install persephone
RUN CC=/usr/bin/clang-19 CXX=/usr/bin/clang++-19 cmake -B builddir -S . -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=/usr/bin/clang++-19 -DCMAKE_C_COMPILER=/usr/bin/clang-19 -DCMAKE_INSTALL_PREFIX=/persephone && cmake --build builddir --config Release && cmake --install builddir --config Release

WORKDIR /build/builddir

ENV SERVER_NAME=localhost
EXPOSE 8008 8448

# At runtime, generate TLS cert based on the CA now mounted at /ca
# At runtime, replace the SERVER_NAME with what we are told
CMD /build/run_postgres.sh && openssl genrsa -out server.key 2048 && echo "Generated opennsl server.key" && \
 sed -i "s/  server_name: localhost/  server_name: ${SERVER_NAME}/g" /build/complement/config.yaml && echo "Generated config file" && \
 openssl req -new -sha256 -key server.key -subj "/C=DE/ST=CA/O=MyOrg, Inc./CN=$SERVER_NAME" -out server.csr && echo "Generated coserver.csr" && \
 openssl x509 -req -in server.csr -CA /complement/ca/ca.crt -CAkey /complement/ca/ca.key -CAcreateserial -out server.crt -days 1 -sha256 && echo "Generated ca file" && \
 cp /build/complement/config.yaml ./config.yaml && echo "Copied config file" && \
 cp /complement/ca/ca.crt /usr/local/share/ca-certificates/ && update-ca-certificates && echo "Updated CA Certs. Starting persephone next" && \
 ./persephone