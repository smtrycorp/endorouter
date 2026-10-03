#!/usr/bin/env bash
# The harder suite (cases-hard.jsonl) against strict, balanced and LiteLLM. Same prerequisites as run_all.sh.
set -u
cd "$(dirname "$0")/.."
SR=.venv/bin/endorouter
CASES=src/endorouter/leakbench/cases-hard.jsonl
# a previous run's servers may still be shutting down: wait until every port this script uses is free
for port in 8795 8796 8797 8798 8799 8800 8801; do
  for i in $(seq 1 60); do lsof -iTCP:$port -sTCP:LISTEN >/dev/null 2>&1 || break; sleep 1; done
done
pids=()
(cd bench && LITELLM_TELEMETRY=False .litellm-venv/bin/litellm --config litellm-leakbench.yaml --host 127.0.0.1 --port 8796 > litellm.log 2>&1) & pids+=($!)
$SR serve -c bench/leakbench-strict.yaml --port 8797 > /dev/null 2>&1 & pids+=($!)
$SR serve -c bench/leakbench-balanced.yaml --port 8795 > /dev/null 2>&1 & pids+=($!)
.venv/bin/python bench/local_shim.py 8801 > bench/shim.log 2>&1 & pids+=($!)
for i in $(seq 1 90); do curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8796/health/liveliness | grep -q 200 && break; sleep 1; done
$SR leakbench --cases $CASES --base-url http://127.0.0.1:8796/v1 --no-provenance --model cloud-model --extra-body '{"metadata":{"session_id":"lb-{id}"}}' > bench/hard-litellm.json; echo "litellm exit $?"
$SR leakbench --cases $CASES --base-url http://127.0.0.1:8797/v1 > bench/hard-strict.json; echo "strict exit $?"
$SR leakbench --cases $CASES --base-url http://127.0.0.1:8795/v1 > bench/hard-balanced.json; echo "balanced exit $?"
pkill -f "litellm --config litellm-leakbench.yaml"; kill "${pids[@]}" 2>/dev/null; wait 2>/dev/null
