#!/bin/bash

# Script to demonstrate mutex monitoring functionality

set -e

echo "Building mutex monitor and test program..."
make all

echo "Starting mutex monitor in background..."
sudo ./target/release/mutex_monitor \
    --target ./samples/mutex_test \
    --max-delay 500 \
    --stats-interval 2 &

MONITOR_PID=$!

# Give the monitor time to attach
sleep 2

echo "Running test program..."
./samples/mutex_test

echo "Stopping mutex monitor..."
sudo kill $MONITOR_PID 2>/dev/null || true

echo "Done!"