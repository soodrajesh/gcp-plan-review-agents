#!/usr/bin/env bash
# Dogfood: plan this repo's own Terraform and have the agents review the plan. No cloud changes.
source "$(dirname "$0")/lib.sh"
need terraform
tf_init
plan="$(mktemp -t prself.XXXXXX)"
TF_VAR_image="placeholder" $TF plan -input=false -no-color -out="$plan" >/dev/null
$TF show -json "$plan" > "$plan.json"
"$ROOT/.venv/bin/planreview" review "$plan.json" --llm "${LLM:-none}" || true
rm -f "$plan" "$plan.json"
