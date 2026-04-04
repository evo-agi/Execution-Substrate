#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/71_diagnostics_summary.sh <bundle_dir|bundle.json>

Notes:
  This helper reads the bounded diagnostics bundle produced by scripts/70_diagnostics.sh
  and prints a compact operator-facing summary. It does not collect new diagnostics.
EOF
}

fail_usage() {
  printf '%s\n\n' "$1" >&2
  usage >&2
  exit 1
}

resolve_bundle_json_path() {
  local candidate=$1

  if [[ -d "${candidate}" ]]; then
    candidate="${candidate%/}/bundle.json"
  fi

  if [[ ! -f "${candidate}" ]]; then
    printf 'bundle.json not found: %s\n' "${candidate}" >&2
    return 1
  fi

  printf '%s\n' "${candidate}"
}

if (($# != 1)); then
  usage >&2
  exit 1
fi

case "$1" in
  -h|--help)
    usage
    exit 0
    ;;
esac

BUNDLE_JSON_PATH="$(resolve_bundle_json_path "$1")" || fail_usage "unable to read diagnostics bundle"

python3 - <<'PY' "${BUNDLE_JSON_PATH}"
import json
import pathlib
import sys

bundle_path = pathlib.Path(sys.argv[1])
payload = json.loads(bundle_path.read_text(encoding="utf-8"))

bundle_status = str(payload.get("bundle_status") or "unknown").strip() or "unknown"
bundle_dir = str(payload.get("bundle_dir") or bundle_path.parent).strip() or str(bundle_path.parent)
category = str(payload.get("category") or "").strip()
run_id = str(payload.get("run_id") or "").strip()
troubleshooting_matrix = str(payload.get("troubleshooting_matrix") or "").strip()
components = payload.get("components") or []


def component_lines(items):
    for component in items:
        name = str(component.get("name") or "").strip() or "unknown"
        status = str(component.get("status") or "unknown").strip() or "unknown"
        detail = str(component.get("detail") or "").strip()
        if detail:
            yield f"- {name} [{status}] -> {detail}"
        else:
            yield f"- {name} [{status}]"


critical_attention = [
    c
    for c in components
    if str(c.get("criticality") or "").strip() == "critical"
    and str(c.get("status") or "").strip() != "collected"
]
collected_signals = [
    c
    for c in components
    if str(c.get("status") or "").strip() == "collected"
]
optional_attention = [
    c
    for c in components
    if str(c.get("criticality") or "").strip() != "critical"
    and str(c.get("status") or "").strip() != "collected"
]

print("Diagnostics bundle summary")
print(f"bundle_json={bundle_path}")
print(f"bundle_status={bundle_status}")
print(f"bundle_dir={bundle_dir}")
if category:
    print(f"category={category}")
if run_id:
    print(f"run_id={run_id}")
if troubleshooting_matrix:
    print(f"troubleshooting_matrix={troubleshooting_matrix}")

if critical_attention:
    print("")
    print("Critical items needing attention:")
    for line in component_lines(critical_attention):
        print(line)

if collected_signals:
    print("")
    print("Collected signals:")
    for line in component_lines(collected_signals):
        print(line)

if optional_attention:
    print("")
    print("Optional items that were not collected:")
    for line in component_lines(optional_attention):
        print(line)

print("")
print("Use the troubleshooting matrix above as the source of truth for the next operator action.")
PY
