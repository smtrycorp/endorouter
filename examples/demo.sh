#!/usr/bin/env bash
# Three decisions, no model needed: `explain` runs the policy and prints the decision without sending anything.
set -euo pipefail
CFG="$(python3 -c 'import endorouter, os; print(os.path.join(os.path.dirname(endorouter.__file__), "example.yaml"))')"

echo "1. No provenance: stays local"
echo "How do I reverse a list in Python?" | endorouter explain -c "$CFG"

echo; echo "2. Public source: the cloud is permitted"
echo "Summarise this page." | endorouter explain -c "$CFG" --source docs/public/intro.md --label public

echo; echo "3. Public label, but a key in the text: private, local only"
echo "Why does AKIAIOSFODNN7EXAMPLE fail?" | endorouter explain -c "$CFG" --source docs/public/intro.md --label public
