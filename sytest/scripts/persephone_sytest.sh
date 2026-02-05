#!/bin/bash
# Sytest runner script for Persephone
# Based on dendrite_sytest.sh from the sytest repository
set -e

PERSEPHONE_BINDIR="${PERSEPHONE_BINDIR:-/persephone/bin}"

echo "=== Persephone Sytest Runner ==="
echo "Persephone binary dir: $PERSEPHONE_BINDIR"

# Verify binary exists
if [ ! -x "$PERSEPHONE_BINDIR/persephone" ]; then
    echo "ERROR: Persephone binary not found at $PERSEPHONE_BINDIR/persephone"
    exit 1
fi

# Start PostgreSQL - find the installed version dynamically
echo "Starting PostgreSQL..."
PG_VERSION=$(ls /etc/postgresql/ 2>/dev/null | sort -rn | head -1)
if [ -n "$PG_VERSION" ]; then
    echo "Found PostgreSQL version: $PG_VERSION"
    pg_ctlcluster "$PG_VERSION" main start 2>/dev/null || service postgresql start 2>/dev/null || true
else
    service postgresql start 2>/dev/null || true
fi

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL..."
for i in $(seq 1 30); do
    if pg_isready -q 2>/dev/null; then
        echo "PostgreSQL is ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: PostgreSQL did not start in time"
        exit 1
    fi
    sleep 1
done

# Create test databases (similar to dendrite_sytest.sh)
echo "Creating test databases..."
for db in pg1 pg2 sytest_template; do
    su -c "createdb --encoding=UTF8 $db 2>/dev/null || true" postgres
done

# Determine whitelist/blacklist files
WHITELIST_ARG=""
if [ -f "/persephone/whitelist.txt" ]; then
    WHITELIST_ARG="-W /persephone/whitelist.txt"
fi

BLACKLIST_ARG=""
if [ -f "/persephone/blacklist.txt" ]; then
    BLACKLIST_ARG="-B /persephone/blacklist.txt"
fi

# Trap to ensure logs are copied on exit
mkdir -p /logs
cleanup() {
    echo "Copying server logs..."
    cp -r /work/server-* /logs/ 2>/dev/null || true
}
trap cleanup EXIT

# Run sytest
echo "=== Running Sytest ==="
echo "Implementation: Persephone"
echo "Binary directory: $PERSEPHONE_BINDIR"

cd /sytest
mkdir -p /work

TEST_STATUS=0
./run-tests.pl \
    -I Persephone \
    -d "$PERSEPHONE_BINDIR" \
    --work-directory /work \
    $WHITELIST_ARG \
    $BLACKLIST_ARG \
    -O tap \
    --all \
    --exclude-deprecated \
    "$@" \
    2>&1 | tee /logs/results.tap || TEST_STATUS=$?

echo ""
echo "=== Test Run Complete ==="
echo "Exit status: $TEST_STATUS"

exit $TEST_STATUS
