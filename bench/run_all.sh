#!/usr/bin/env bash
# Re-run every leakbench configuration in bench/RESULTS.md. Needs: .venv with sovereign-router, bench/.litellm-venv
# with litellm 1.103.1, and (for balanced) a local completion route for bench/local_shim.py (SHIM_UPSTREAM, SHIM_KEY).
set -u
cd "$(dirname "$0")/.."
SR=.venv/bin/sovereign-router
pids=()
(cd bench && LITELLM_TELEMETRY=False .litellm-venv/bin/litellm --config litellm-leakbench.yaml --host 127.0.0.1 --port 8796 > litellm.log 2>&1) & pids+=($!)
$SR serve -c bench/leakbench-strict.yaml --port 8797 > /dev/null 2>&1 & pids+=($!)
$SR serve -c bench/leakbench-passthrough.yaml --port 8798 > /dev/null 2>&1 & pids+=($!)
$SR serve -c bench/leakbench-balanced.yaml --port 8795 > /dev/null 2>&1 & pids+=($!)
.venv/bin/python bench/local_shim.py 8801 > bench/shim.log 2>&1 & pids+=($!)
for i in $(seq 1 90); do curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8796/health/liveliness | grep -q 200 && break; sleep 1; done
$SR leakbench --base-url http://127.0.0.1:8796/v1 --no-provenance --model cloud-model --extra-body '{"metadata":{"session_id":"lb-{id}"}}' > bench/result-litellm.json; echo "litellm exit $?"
$SR leakbench --base-url http://127.0.0.1:8797/v1 > bench/result-strict.json; echo "strict exit $?"
$SR leakbench --base-url http://127.0.0.1:8797/v1 --no-provenance > bench/result-strict-noprov.json; echo "strict-noprov exit $?"
$SR leakbench --base-url http://127.0.0.1:8798/v1 > bench/result-control-passthrough.json; echo "control exit $?"
$SR leakbench --base-url http://127.0.0.1:8795/v1 > bench/result-balanced.json; echo "balanced exit $?"
pkill -f "litellm --config litellm-leakbench.yaml"; kill "${pids[@]}" 2>/dev/null
