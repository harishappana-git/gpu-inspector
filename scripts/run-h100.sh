#!/usr/bin/env bash
# Bounded one-selected-GPU acceptance run from a prepared development bundle.
set -Eeuo pipefail
umask 077
bundle_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
device=
sku=h100-pcie-80gb
tier=standard
budget=300
memory=1024
output_dir="./h100-run-$(date -u +%Y%m%dT%H%M%SZ)-$$"
extra=()
usage() {
  cat <<'EOF'
Usage: bash scripts/run-h100.sh --device GPU-<full-uuid> [--bundle DIR]
       [--expected-sku h100-pcie-80gb|h100-sxm-80gb|h100-nvl-94gb]
       [--tier quick|standard] [--budget-seconds 300] [--memory-mib 1024]
       [--output NEW_DIR] [--dcgm] [--dcgm-budget-seconds 40]
       [--advisory SIGNED_PACK --advisory-public-key PUBLIC_PEM]
Uses a signed development worker in a prepared bundle. Does not build/install,
change GPU settings, enable busy-GPU testing, or touch peer devices. Retains
terminal output, verified report, per-scan checklist and exit status separately.
Exit codes follow gri scan; INCONCLUSIVE (3) is expected without qualification.
EOF
}
while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --dcgm) extra+=(--dcgm); shift ;;
    --device|--bundle|--expected-sku|--tier|--budget-seconds|--memory-mib|--output|--dcgm-budget-seconds|--advisory|--advisory-public-key)
      (($# >= 2)) || { usage >&2; exit 1; }
      case "$1" in
        --device) device=$2 ;;
        --bundle) bundle_dir=$2 ;;
        --expected-sku) sku=$2 ;;
        --tier) tier=$2 ;;
        --budget-seconds) budget=$2 ;;
        --memory-mib) memory=$2 ;;
        --output) output_dir=$2 ;;
        *) extra+=("$1" "$2") ;;
      esac
      shift 2 ;;
    *) usage >&2; exit 1 ;;
  esac
done
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Run requires native Linux x86-64.' >&2; exit 1; }
[[ "$device" =~ ^GPU-[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]] || { echo 'Supply the full authorized GPU UUID.' >&2; exit 1; }
case "$sku" in h100-pcie-80gb|h100-sxm-80gb|h100-nvl-94gb) ;; *) echo 'Unsupported H100 variant.' >&2; exit 1 ;; esac
bundle_dir=$(cd -- "$bundle_dir" && pwd -P)
for file in bin/gri libexec/gri-cuda-worker worker-envelope.json worker-public.pem SHA256SUMS; do
  [[ -f "$bundle_dir/$file" ]] || { echo "Incomplete bundle: $file" >&2; exit 1; }
done
(cd -- "$bundle_dir" && sha256sum --check --status SHA256SUMS)
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] || { echo 'Output must be new; previous attempts are preserved.' >&2; exit 1; }
mkdir -p -- "$(dirname -- "$output_dir")"
mkdir -m 700 -- "$output_dir"
output_dir=$(cd -- "$output_dir" && pwd -P)
gri="$bundle_dir/bin/gri"
echo "Selected scope: $device / $sku; $tier; ${budget}s; ${memory}MiB."
echo "Retaining live output and evidence in $output_dir"
# Let gri receive terminal SIGINT and finish its partial journal/report.
trap ':' INT
set +e
"$gri" scan --device "$device" --expected-sku "$sku" --tier "$tier" \
  --budget-seconds "$budget" --memory-mib "$memory" --seed 42 \
  --worker "$bundle_dir/libexec/gri-cuda-worker" \
  --worker-manifest "$bundle_dir/worker-envelope.json" \
  --worker-public-key "$bundle_dir/worker-public.pem" \
  --allow-unqualified-worker --output "$output_dir/evidence" "${extra[@]}" \
  2>&1 | tee "$output_dir/terminal.log"
pipeline_status=("${PIPESTATUS[@]}")
scan_status=${pipeline_status[0]}
log_status=${pipeline_status[1]}
set -e
verify_status=1
checklist_status=1
if [[ -f "$output_dir/evidence/report.json" ]]; then
  set +e
  "$gri" verify --report-dir "$output_dir/evidence" > "$output_dir/verification.log" 2>&1
  verify_status=$?
  if ((verify_status == 0)); then
    "$gri" checklist --report "$output_dir/evidence/report.json" --json > "$output_dir/checklist.json"
    checklist_status=$?
    "$gri" checklist --report "$output_dir/evidence/report.json" > "$output_dir/remaining-checklist.txt"
    text_checklist_status=$?
    if ((checklist_status == 0)); then checklist_status=$text_checklist_status; fi
  fi
  set -e
fi
printf '{"scan_exit_code":%d,"log_exit_code":%d,"verify_exit_code":%d,"checklist_exit_code":%d,"release_qualified":false}\n' \
  "$scan_status" "$log_status" "$verify_status" "$checklist_status" > "$output_dir/run-status.json"
echo "Scan exit: $scan_status; report verification: $verify_status; checklist: $checklist_status"
echo "Output: $output_dir"
if ((log_status != 0 || verify_status != 0 || checklist_status != 0)); then exit 1; fi
exit "$scan_status"
