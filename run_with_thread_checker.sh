#!/usr/bin/env bash

# Command to run
COMMAND="/home/aoli/repos/rpc25519/rpc.test -test.v -test.run 016"

echo "Starting command: $COMMAND"
echo "Monitoring thread count and names..."

# Start the command in background and get its PID
$COMMAND &
PID=$!

# Initialize variables to track thread count
MAX_THREADS=0
CURRENT_THREADS=0
declare -A ALL_THREAD_NAMES

# Function to get thread names
get_thread_names() {
    local pid=$1
    local names=()
    
    if [ -d "/proc/$pid/task" ]; then
        for tid in /proc/$pid/task/*; do
            if [ -d "$tid" ]; then
                tid_num=$(basename "$tid")
                if [ -f "$tid/comm" ]; then
                    thread_name=$(cat "$tid/comm" 2>/dev/null)
                    if [ -n "$thread_name" ]; then
                        names+=("$tid_num:$thread_name")
                        ALL_THREAD_NAMES["$thread_name"]=1
                    fi
                fi
            fi
        done
    fi
    
    printf '%s\n' "${names[@]}"
}

# Monitor the process while it's running
while kill -0 $PID 2>/dev/null; do
    # Get current thread count from /proc/PID/status
    if [ -f "/proc/$PID/status" ]; then
        CURRENT_THREADS=$(grep "^Threads:" /proc/$PID/status | awk '{print $2}')
        
        # Update maximum if current is higher
        if [ "$CURRENT_THREADS" -gt "$MAX_THREADS" ]; then
            MAX_THREADS=$CURRENT_THREADS
            echo "New max threads: $MAX_THREADS"
            echo "Current thread names:"
            get_thread_names $PID | while read line; do
                echo "  $line"
            done
            echo ""
        fi
    fi
    
    # Sleep briefly to avoid excessive CPU usage
    sleep 0.1
done

# Wait for the process to complete and get exit status
wait $PID
EXIT_STATUS=$?

echo ""
echo "Command completed with exit status: $EXIT_STATUS"
echo "Maximum number of threads created: $MAX_THREADS"
echo ""
echo "All thread names encountered:"
for thread_name in "${!ALL_THREAD_NAMES[@]}"; do
    echo "  $thread_name"
done
