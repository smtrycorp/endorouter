# Shared by run_all.sh and run_hard.sh: start the gateways under test, wait until each answers, stop exactly the
# processes started here on any exit, and judge every leakbench exit status.
set -euo pipefail
cd "$(dirname "$0")/.."
SR=.venv/bin/endorouter
[ -x "$SR" ] || { echo "missing $SR: run 'python3 -m venv .venv && .venv/bin/pip install -e .' first" >&2; exit 1; }
[ -x bench/.litellm-venv/bin/litellm ] || { echo "missing bench/.litellm-venv: see bench/RESULTS.md" >&2; exit 1; }

# which code produced these results: the commit, and whether the tree had uncommitted changes
{ echo "commit $(git rev-parse HEAD)"; [ -z "$(git status --porcelain -- src)" ] || echo "src had uncommitted changes"
  echo "run $(date -u +%Y-%m-%dT%H:%MZ)"; } > "bench/run-info-$(basename "$0" .sh).txt"

pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup EXIT

for port in 8795 8796 8797 8798 8799 8800; do  # a previous run's servers may still be shutting down
  for _ in $(seq 1 60); do lsof -iTCP:$port -sTCP:LISTEN >/dev/null 2>&1 || break; sleep 1; done
  if lsof -iTCP:$port -sTCP:LISTEN >/dev/null 2>&1; then echo "port $port is still in use" >&2; exit 1; fi
done

ready() {  # ready <name> <url>: wait up to 90 s for a 200, or stop the run
  for _ in $(seq 1 90); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$2")" = 200 ] && return 0
    sleep 1
  done
  echo "$1 did not come up at $2" >&2; exit 1
}

start_litellm() {
  (cd bench && LITELLM_TELEMETRY=False exec .litellm-venv/bin/litellm --config litellm-leakbench.yaml \
     --host 127.0.0.1 --port 8796 > litellm.log 2>&1) & pids+=($!)
  ready litellm http://127.0.0.1:8796/health/liveliness
}

start_router() {  # start_router <config> <port>
  $SR serve -c "$1" --port "$2" > /dev/null 2>&1 & pids+=($!)
  ready "endorouter $1" "http://127.0.0.1:$2/healthz"
}

# Balanced mode needs a local OpenAI-compatible model server on 127.0.0.1:8801 for its classifier (see RESULTS.md).
classifier_up() { [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8801/v1/models)" = 200 ]; }

failed=0
bench() {  # bench <name> <expect: clean|any> <output> <leakbench args...>: 5 = invalid run, always a failure
  local name=$1 expect=$2 out=$3; shift 3
  local status=0
  $SR leakbench "$@" > "$out" || status=$?
  echo "$name: exit $status"
  if [ $status -eq 5 ] || { [ $status -ne 0 ] && [ $status -ne 4 ]; } || { [ "$expect" = clean ] && [ $status -ne 0 ]; }; then
    echo "  $name FAILED (expected ${expect})" >&2; failed=1
  fi
}
