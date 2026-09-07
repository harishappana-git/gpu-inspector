#!/usr/bin/env bash
# Hermetic orchestration test. Runs under Linux, macOS, or Git Bash on Windows.
# Mock uname and gri exercise shell behavior only: no GPU, DCGM, kernel logs,
# CUDA worker, real report verification, or native Linux runtime is tested.
set -Eeuo pipefail
umask 077
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
mkdir -p -- "$repo_dir/build"
fixture_dir=$(mktemp -d "$repo_dir/build/h100-runner-fixture.XXXXXX")
bundle_dir="$fixture_dir/mock bundle"
mock_tools="$fixture_dir/mock-tools"
mkdir -p -- "$bundle_dir/bin" "$bundle_dir/libexec" "$mock_tools"

cat > "$mock_tools/uname" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  -s) printf 'Linux\n' ;;
  -m) printf 'x86_64\n' ;;
  *) echo 'Unexpected mock uname invocation' >&2; exit 90 ;;
esac
EOF
cat > "$bundle_dir/bin/gri" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
command_name=${1:?Missing fixture command}
shift
printf '%s\n' "$command_name" >> "$MOCK_CALLS"
case "$command_name" in
  scan)
    report_dir=
    while (($#)); do
      case "$1" in
        --output) report_dir=$2; shift 2 ;;
        --allow-busy) echo 'Desktop busy consent must not be added by H100 runner' >&2; exit 91 ;;
        --allow-unqualified-worker) shift ;;
        --device|--expected-sku|--tier|--budget-seconds|--memory-mib|--seed|--worker|--worker-manifest|--worker-public-key)
          (($# >= 2)) || exit 92
          shift 2 ;;
        *) echo "Unexpected mock scan argument: $1" >&2; exit 93 ;;
      esac
    done
    [[ -n "$report_dir" ]] || exit 94
    if [[ "$MOCK_WRITE_REPORT" == 1 ]]; then
      mkdir -- "$report_dir"
      printf '{"synthetic_orchestration_fixture":true}\n' > "$report_dir/report.json"
    fi
    echo 'MOCK scan stdout: no GPU operation'
    echo 'MOCK scan stderr: no GPU operation' >&2
    exit "$MOCK_SCAN_STATUS" ;;
  verify)
    [[ "$1" == --report-dir && -f "$2/report.json" && $# == 2 ]] || exit 95
    echo 'MOCK verification only; does not verify real report evidence'
    exit "$MOCK_VERIFY_STATUS" ;;
  checklist)
    [[ "$1" == --report && -f "$2" ]] || exit 96
    if [[ "${3:-}" == --json ]]; then
      echo '{"synthetic_orchestration_fixture":true,"release_qualified":false}'
      exit "$MOCK_JSON_STATUS"
    fi
    [[ $# == 2 ]] || exit 97
    echo 'MOCK checklist: no release qualification'
    exit "$MOCK_TEXT_STATUS" ;;
  *) echo 'Mock forbids all other commands' >&2; exit 98 ;;
esac
EOF
# A non-executable marker prevents accidental use even if orchestration changes.
echo 'Synthetic worker marker; never executable' > "$bundle_dir/libexec/gri-cuda-worker"
echo 'Synthetic envelope marker; never trusted' > "$bundle_dir/worker-envelope.json"
echo 'Synthetic public key marker; no key material' > "$bundle_dir/worker-public.pem"
chmod 700 -- "$mock_tools/uname" "$bundle_dir/bin/gri"
(cd -- "$bundle_dir" && sha256sum bin/gri libexec/gri-cuda-worker worker-envelope.json worker-public.pem > SHA256SUMS)

device=GPU-00000000-0000-0000-0000-000000000001
run_case() {
  local name=$1 expected_exit=$2 scan=$3 verify=$4 json=$5 text=$6 log=$7 write_report=$8
  local case_dir="$fixture_dir/$name" result actual expected_verify expected_checklist
  mkdir -p -- "$case_dir/bin"
  if ((log != 0)); then
    cat > "$case_dir/bin/tee" <<'EOF'
#!/usr/bin/env bash
# Drain the pipeline so this test isolates logging failure from SIGPIPE.
cat >/dev/null
exit 9
EOF
    chmod 700 -- "$case_dir/bin/tee"
  fi
  set +e
  PATH="$case_dir/bin:$mock_tools:$PATH" MOCK_CALLS="$case_dir/calls.log" \
    MOCK_SCAN_STATUS="$scan" MOCK_VERIFY_STATUS="$verify" MOCK_JSON_STATUS="$json" \
    MOCK_TEXT_STATUS="$text" MOCK_WRITE_REPORT="$write_report" \
    bash "$repo_dir/scripts/run-h100.sh" --bundle "$bundle_dir" --device "$device" \
      --expected-sku h100-pcie-80gb --output "$case_dir/run output" \
      > "$case_dir/runner.log" 2>&1
  actual=$?
  set -e
  [[ "$actual" == "$expected_exit" ]] || { echo "$name: expected exit $expected_exit, got $actual; $case_dir/runner.log" >&2; return 1; }
  expected_verify=$verify
  expected_checklist=$json
  if ((json == 0)); then expected_checklist=$text; fi
  if ((write_report == 0)); then expected_verify=1; fi
  if ((expected_verify != 0)); then expected_checklist=1; fi
  printf -v result '{"scan_exit_code":%d,"log_exit_code":%d,"verify_exit_code":%d,"checklist_exit_code":%d,"release_qualified":false}' \
    "$scan" "$log" "$expected_verify" "$expected_checklist"
  [[ $(cat -- "$case_dir/run output/run-status.json") == "$result" ]] || { echo "$name: incorrect retained exit statuses" >&2; return 1; }
  if ((write_report == 0)); then
    [[ $(cat -- "$case_dir/calls.log") == scan ]] || { echo "$name: verification ran without a report" >&2; return 1; }
  elif ((verify != 0)); then
    [[ $(cat -- "$case_dir/calls.log") == $'scan\nverify' ]] || { echo "$name: checklist ran after failed verification" >&2; return 1; }
  else
    [[ $(cat -- "$case_dir/calls.log") == $'scan\nverify\nchecklist\nchecklist' ]] || { echo "$name: report workflow was incomplete" >&2; return 1; }
  fi
  if ((log == 0)); then
    grep -Fq 'MOCK scan stdout' "$case_dir/run output/terminal.log"
    grep -Fq 'MOCK scan stderr' "$case_dir/run output/terminal.log"
  fi
  printf 'PASS %s (mock orchestration only)\n' "$name"
}

run_case inconclusive-preserved 3 3 0 0 0 0 1
run_case failed-scan-preserved 2 2 0 0 0 0 1
run_case verification-failure 1 3 7 0 0 0 1
run_case json-checklist-failure 1 3 0 8 0 0 1
run_case text-checklist-failure 1 3 0 0 8 0 1
run_case terminal-log-failure 1 3 0 0 0 9 1
run_case missing-report 1 3 0 0 0 0 0

# The actual sha256sum tool must reject a changed bundle before mock execution.
echo 'Changed synthetic marker' >> "$bundle_dir/libexec/gri-cuda-worker"
set +e
PATH="$mock_tools:$PATH" MOCK_CALLS="$fixture_dir/checksum-calls.log" \
  bash "$repo_dir/scripts/run-h100.sh" --bundle "$bundle_dir" --device "$device" \
    --output "$fixture_dir/checksum-output" > "$fixture_dir/checksum.log" 2>&1
checksum_status=$?
set -e
[[ "$checksum_status" == 1 && ! -e "$fixture_dir/checksum-calls.log" && ! -e "$fixture_dir/checksum-output" ]] || { echo 'Changed bundle entered the scan workflow' >&2; exit 1; }
echo 'PASS checksum rejection before execution (mock bundle only)'
echo "Hermetic runner fixtures retained in: $fixture_dir"
