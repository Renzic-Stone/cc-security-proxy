#!/bin/bash
# Sandbox entrypoint: run a script, capture everything
set -e

SCRIPT_FILE="$1"
TIMEOUT="${2:-30}"

if [ ! -f "$SCRIPT_FILE" ]; then
    echo "ERROR: script file not found: $SCRIPT_FILE"
    exit 1
fi

# Run with timeout, capture exit code
timeout "$TIMEOUT" bash "$SCRIPT_FILE" 2>&1
EXIT_CODE=$?

if [ $EXIT_CODE -eq 124 ]; then
    echo "SANDBOX_TIMEOUT"
    exit 124
fi

exit $EXIT_CODE
