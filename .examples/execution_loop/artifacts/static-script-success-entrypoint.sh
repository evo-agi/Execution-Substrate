#!/bin/sh
set -eu

echo START-BANNER
for i in 1 2 3; do
  echo HEARTBEAT:$i
  sleep 1
done
echo "{\"status\":\"ok\",\"artifact_digest\":\"${EXEC_ARTIFACT_DIGEST}\"}"
