#!/bin/bash
# Sytest runner script for Persephone
set -e

SYTEST_DIR="${SYTEST_DIR:-/sytest}"
SRC_DIR="${SRC_DIR:-/src}"
BUILD_DIR="${BUILD_DIR:-/build}"
LOGS_DIR="${LOGS_DIR:-/logs}"
WORK_DIR="${WORK_DIR:-/work}"
BINARY_DIR="${BINARY_DIR:-/usr/local/bin}"

cd "$SYTEST_DIR"

echo "=== Persephone Sytest Runner ==="
echo "Source directory: $SRC_DIR"
echo "Build directory: $BUILD_DIR"
echo "Logs directory: $LOGS_DIR"

# Install perl dependencies
echo "Installing Perl dependencies..."
./install-deps.pl

# Build Persephone if binary doesn't exist
if [ ! -f "$BINARY_DIR/persephone" ]; then
    echo "Building Persephone from source..."

    if [ ! -d "$SRC_DIR/src" ]; then
        echo "ERROR: Source directory $SRC_DIR does not contain Persephone source"
        exit 1
    fi

    cd "$SRC_DIR"

    # Configure
    CC=clang-18 CXX=clang++-18 cmake -B "$BUILD_DIR" -S . \
        -DCMAKE_BUILD_TYPE=Release \
        -DDISABLE_TESTS=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld-18" \
        -DCMAKE_SHARED_LINKER_FLAGS="-fuse-ld=lld-18"

    # Build
    cmake --build "$BUILD_DIR" -j$(nproc)

    # Install
    cmake --install "$BUILD_DIR"

    echo "Persephone built and installed successfully"
else
    echo "Using existing Persephone binary at $BINARY_DIR/persephone"
fi

# Verify binary exists and is executable
if [ ! -x "$BINARY_DIR/persephone" ]; then
    echo "ERROR: Persephone binary not found or not executable at $BINARY_DIR/persephone"
    exit 1
fi

echo "Persephone version check:"
"$BINARY_DIR/persephone" --version 2>/dev/null || echo "(version flag not supported)"

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

cd "$SYTEST_DIR"

# Determine whitelist/blacklist files
WHITELIST_ARG=""
if [ -f "$SRC_DIR/sytest/whitelist.txt" ]; then
    WHITELIST_ARG="-W $SRC_DIR/sytest/whitelist.txt"
elif [ -f "/sytest/persephone_whitelist.txt" ]; then
    WHITELIST_ARG="-W /sytest/persephone_whitelist.txt"
fi

BLACKLIST_ARG=""
if [ -f "$SRC_DIR/sytest/blacklist.txt" ]; then
    BLACKLIST_ARG="-B $SRC_DIR/sytest/blacklist.txt"
elif [ -f "/sytest/persephone_blacklist.txt" ]; then
    BLACKLIST_ARG="-B /sytest/persephone_blacklist.txt"
fi

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
