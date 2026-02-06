#!/bin/bash
# Entrypoint wrapper for Persephone sytest
# Downloads sytest, installs our plugin, and runs tests
set -e

echo "=== Persephone Sytest Entrypoint ==="

export SYTEST_BRANCH="${SYTEST_BRANCH:-develop}"

# Check if sytest is already present
if [ ! -f /sytest/run-tests.pl ]; then
    echo "Downloading sytest (branch: $SYTEST_BRANCH)..."
    mkdir -p /sytest
    if ! wget -q "https://github.com/matrix-org/sytest/archive/${SYTEST_BRANCH}.tar.gz" -O /tmp/sytest.tar.gz; then
        echo "Branch $SYTEST_BRANCH not found, falling back to develop..."
        wget -q "https://github.com/matrix-org/sytest/archive/develop.tar.gz" -O /tmp/sytest.tar.gz
    fi
    tar -xzf /tmp/sytest.tar.gz --strip-components=1 -C /sytest
    rm /tmp/sytest.tar.gz
fi

# Install sytest CA certificate into the system trust store so that
# outbound federation HTTPS requests trust the sytest mock servers.
if [ -f /sytest/keys/ca.crt ]; then
    echo "Installing sytest CA certificate..."
    cp /sytest/keys/ca.crt /usr/local/share/ca-certificates/sytest-ca.crt
    update-ca-certificates
fi

# Install our plugin files
echo "Installing Persephone sytest plugin..."
cp -r /persephone/sytest-plugin/lib/* /sytest/lib/

# Copy our runner script
mkdir -p /sytest/scripts
cp /persephone/sytest-plugin/persephone_sytest.sh /sytest/scripts/

# Install sytest perl dependencies
echo "Installing sytest Perl dependencies..."
cd /sytest
./install-deps.pl

# Now run our test script
echo "Starting Persephone tests..."
exec /sytest/scripts/persephone_sytest.sh "$@"
