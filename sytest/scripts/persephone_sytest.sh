#!/bin/bash
# Sytest runner script for Persephone
set -e

SYTEST_DIR="${SYTEST_DIR:-/sytest}"
LOGS_DIR="${LOGS_DIR:-/logs}"
WORK_DIR="${WORK_DIR:-/work}"
PERSEPHONE_BINARY="${PERSEPHONE_BINARY:-/persephone/bin/persephone}"

cd "$SYTEST_DIR"

echo "=== Persephone Sytest Runner ==="
echo "Sytest directory: $SYTEST_DIR"
echo "Logs directory: $LOGS_DIR"
echo "Persephone binary: $PERSEPHONE_BINARY"

# Verify binary exists and is executable
if [ ! -x "$PERSEPHONE_BINARY" ]; then
    echo "ERROR: Persephone binary not found or not executable at $PERSEPHONE_BINARY"
    exit 1
fi

echo "Persephone version check:"
"$PERSEPHONE_BINARY" --version 2>/dev/null || echo "(version flag not supported)"

# Start PostgreSQL
echo "Starting PostgreSQL..."
service postgresql start 2>/dev/null || pg_ctlcluster 15 main start 2>/dev/null || true

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL..."
for i in $(seq 1 30); do
    if pg_isready -q; then
        echo "PostgreSQL is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "ERROR: PostgreSQL did not start in time"
        exit 1
    fi
    sleep 1
done

# Create work and logs directories
mkdir -p "$WORK_DIR" "$LOGS_DIR"

# Determine whitelist/blacklist files
WHITELIST_ARG=""
if [ -f "/sytest/persephone_whitelist.txt" ]; then
    WHITELIST_ARG="-W /sytest/persephone_whitelist.txt"
fi

BLACKLIST_ARG=""
if [ -f "/sytest/persephone_blacklist.txt" ]; then
    BLACKLIST_ARG="-B /sytest/persephone_blacklist.txt"
fi

# Get the binary directory (parent of the binary)
BINARY_DIR=$(dirname "$PERSEPHONE_BINARY")

# Run sytest
echo "=== Running Sytest ==="
echo "Implementation: Persephone"
echo "Binary directory: $BINARY_DIR"
echo "Whitelist: $WHITELIST_ARG"
echo "Blacklist: $BLACKLIST_ARG"

TEST_STATUS=0
./run-tests.pl \
    -I Persephone \
    -d "$BINARY_DIR" \
    $WHITELIST_ARG \
    $BLACKLIST_ARG \
    -O tap \
    --all \
    --work-directory="$WORK_DIR" \
    --exclude-deprecated \
    "$@" \
    2>&1 | tee "$LOGS_DIR/results.tap" || TEST_STATUS=$?

# Copy server logs
echo "Copying server logs..."
rsync -r --ignore-missing-args --min-size=1 "$WORK_DIR/server-"* "$LOGS_DIR/" 2>/dev/null || true

# Summary
echo ""
echo "=== Test Run Complete ==="
echo "Results: $LOGS_DIR/results.tap"
echo "Server logs: $LOGS_DIR/"
echo "Exit status: $TEST_STATUS"

exit $TEST_STATUS
