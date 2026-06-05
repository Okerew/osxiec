#!/bin/bash
# This is a work in progress.

# Check for minimum number of arguments
if [ "$#" -lt 1 ]; then
    echo "Usage: osxiec -deploym <multi_config_file> [port1 port2 ...]"
    exit 1
fi

multi_config_file="$1"
shift

# Array to store PIDs and ports
pids=()
ports=("$@")

# Function to deploy and keep a container running
deploy_container() {
    local config_file="$1"
    local network_name="$2"
    local port="$3"
    echo "Deploying container with config: $config_file on network: $network_name with port: $port"
    while true; do
        osxiec -deploy "$config_file" "$network_name" -port "$port"
        exit_status=$?
        if [ $exit_status -ne 0 ]; then
            echo "Container exited with status $exit_status, restarting in 5 seconds..."
            sleep 5
        else
            echo "Container exited normally. Not restarting."
            break
        fi
    done
}

# Read the multi_config_file and start each deployment in a separate thread
i=0
while IFS=' ' read -r config_file network_name || [[ -n "$config_file" ]]; do
    if [[ -n "$config_file" && -n "$network_name" ]]; then
        port=${ports[$i]:-$((8080 + i))}  # Increment default port to avoid conflicts
        (deploy_container "$config_file" "$network_name" "$port") &  # Run in background
        pids+=($!)
        echo "Started container process with PID: $! and port: $port"
        ((i++))
    fi
done < "$multi_config_file"

echo "All container processes started. PIDs: ${pids[*]}"

# Function to handle script termination
cleanup() {
    echo "Terminating all container processes..."
    for pid in "${pids[@]}"; do
        kill $pid 2>/dev/null
    done
    exit
}

# Set up trap to call cleanup function on script termination
trap cleanup SIGINT SIGTERM

# Wait for all processes to finish
for pid in "${pids[@]}"; do
    wait $pid
done
