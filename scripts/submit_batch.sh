#!/bin/bash
DIR=${1:-/opt/CAPEv2/ml/samples/malware}
TIMEOUT=${2:-120}
echo "Submitting from: $DIR (timeout: ${TIMEOUT}s)"
count=0
for f in "$DIR"/*.exe; do
    [ -f "$f" ] || continue
    result=$(sudo -u cape /etc/poetry/bin/poetry run python \
        /opt/CAPEv2/utils/submit.py \
        --timeout $TIMEOUT --enforce-timeout --package exe "$f" 2>/dev/null)
    task_id=$(echo "$result" | grep -oP 'ID \K[0-9]+')
    echo "  $(basename $f) → Task #$task_id"
    count=$((count+1)); sleep 2
done
echo "Submitted: $count files"
