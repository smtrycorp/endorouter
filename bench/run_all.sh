#!/usr/bin/env bash
# Re-run every configuration in bench/RESULTS.md on the main suite. Exits non-zero if any run is invalid, or if a
# configuration expected to leak nothing leaked.
source "$(dirname "$0")/lib.sh"
start_litellm
start_router bench/leakbench-strict.yaml 8797
start_router bench/leakbench-passthrough.yaml 8798
bench litellm any bench/result-litellm.json --base-url http://127.0.0.1:8796/v1 --no-provenance --model cloud-model \
  --extra-body '{"metadata":{"session_id":"lb-{id}"}}'
bench strict clean bench/result-strict.json --base-url http://127.0.0.1:8797/v1
bench strict-noprov clean bench/result-strict-noprov.json --base-url http://127.0.0.1:8797/v1 --no-provenance
bench control any bench/result-control-passthrough.json --base-url http://127.0.0.1:8798/v1
if classifier_up; then
  start_router bench/leakbench-balanced.yaml 8795
  bench balanced clean bench/result-balanced.json --base-url http://127.0.0.1:8795/v1
else
  echo "balanced: SKIPPED, no classifier model server on 127.0.0.1:8801" >&2
fi
exit $failed
