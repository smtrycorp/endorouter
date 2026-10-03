#!/usr/bin/env bash
# The harder suite (cases-hard.jsonl) and the boundary suite (cases-boundary.jsonl: secrets sent under a public label,
# where only the detectors stand in the way) against strict, balanced and LiteLLM. Same prerequisites as run_all.sh.
source "$(dirname "$0")/lib.sh"
CASES=src/endorouter/leakbench/cases-hard.jsonl
EDGE=src/endorouter/leakbench/cases-boundary.jsonl
start_litellm
start_router bench/leakbench-strict.yaml 8797
bench litellm any bench/hard-litellm.json --cases $CASES --base-url http://127.0.0.1:8796/v1 --no-provenance \
  --model cloud-model --extra-body '{"metadata":{"session_id":"lb-{id}"}}'
bench strict clean bench/hard-strict.json --cases $CASES --base-url http://127.0.0.1:8797/v1
bench boundary-litellm any bench/boundary-litellm.json --cases $EDGE --base-url http://127.0.0.1:8796/v1 \
  --no-provenance --model cloud-model --extra-body '{"metadata":{"session_id":"lb-{id}"}}'
bench boundary-strict clean bench/boundary-strict.json --cases $EDGE --base-url http://127.0.0.1:8797/v1
if classifier_up; then
  start_router bench/leakbench-balanced.yaml 8795
  bench balanced clean bench/hard-balanced.json --cases $CASES --base-url http://127.0.0.1:8795/v1
  bench boundary-balanced clean bench/boundary-balanced.json --cases $EDGE --base-url http://127.0.0.1:8795/v1
else
  echo "balanced: SKIPPED, no classifier model server on 127.0.0.1:8801" >&2
fi
exit $failed
