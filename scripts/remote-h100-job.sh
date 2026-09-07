#!/usr/bin/env bash
# Owned detached server job. All arguments come from one validated job JSON.
set -Eeuo pipefail
umask 077
job_root=${1:?job root required}
[[ "$job_root" =~ ^/tmp/gri-h100-[0-9a-f]{24}$ && ! -L "$job_root" && -O "$job_root" ]] || exit 1
[[ $(cat "$job_root/owner-marker") == "${job_root##*/}" ]] || exit 1
source_dir="$job_root/source"
stage=setup
finish() {
  local result=$?
  printf '{"job_exit_code":%d,"stage":"%s","release_qualified":false}\n' "$result" "$stage" > "$job_root/job-finished.json.tmp"
  mv -- "$job_root/job-finished.json.tmp" "$job_root/job-finished.json"
}
trap finish EXIT
mapfile -t settings < <(python3 - "$job_root/node-config.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1],encoding='utf-8'))
for key in ('setup_budget_seconds','campaign_budget_seconds','install_system_deps','sanitizer','dcgm','device','expected_sku','cuda_root'):
 value=c[key]
 if isinstance(value,bool): value='true' if value else 'false'
 value=str(value)
 if '\n' in value or '\r' in value: raise ValueError('invalid configuration')
 print(value)
PY
)
[[ ${#settings[@]} == 8 && ${settings[0]} =~ ^[0-9]+$ && ${settings[1]} =~ ^[0-9]+$ ]] || exit 1
setup_args=(--prefix "$job_root/toolchain" --output-env "$job_root/setup.env" --budget-seconds "${settings[0]}")
[[ ${settings[2]} != true ]] || setup_args+=(--install-system-deps)
[[ -z ${settings[7]} ]] || setup_args+=(--cuda-root "${settings[7]}")
echo 'Preparing existing-driver H100 toolchain'
set +e
bash "$source_dir/scripts/setup-h100.sh" "${setup_args[@]}"
setup_exit=$?
set -e
# Copy only normalized setup status/logs; never the sourceable environment,
# download cache, compiler trees or development signing keys.
setup_log="$job_root/setup-summary.log"
python3 - "$job_root/setup.env.json" "$setup_log" "$job_root/toolchain" <<'PY'
import json,pathlib,sys
status=pathlib.Path(sys.argv[1]); output=pathlib.Path(sys.argv[2])
if status.is_file():
 value=json.loads(status.read_text(encoding='utf-8'))
 path=pathlib.Path(value.get('setup_log','')); allowed=pathlib.Path(sys.argv[3]).resolve()
 safe=allowed in path.resolve().parents and not any(p.is_symlink() for p in (path,*path.parents))
 if safe and path.is_file() and path.stat().st_size <= 16<<20:
  output.write_text(path.read_text(encoding='utf-8',errors='replace'),encoding='utf-8')
 else: output.write_text('Setup log unavailable within allowed bounds.\n',encoding='utf-8')
else: output.write_text('Setup did not publish a status manifest.\n',encoding='utf-8')
PY
if ((setup_exit != 0)); then
  mkdir -p -m 700 -- "$job_root/campaign/logs"
  cp -- "$setup_log" "$job_root/campaign/logs/setup.log"
  [[ ! -f "$job_root/setup.env.json" ]] || cp -- "$job_root/setup.env.json" "$job_root/campaign/logs/setup-status.json"
  python3 "$source_dir/scripts/h100-campaign.py" --output "$job_root/campaign" --package-only --failure-reason setup_failed
  stage=setup_failed
  exit 2
fi
source "$job_root/setup.env"
stage=campaign
campaign_args=(--source "$source_dir" --output "$job_root/campaign" --cuda-root "$CUDA_ROOT"
  --total-budget-seconds "${settings[1]}" --setup-log "$setup_log" --setup-status "$job_root/setup.env.json")
[[ ${settings[3]} != true ]] || campaign_args+=(--sanitizer)
[[ ${settings[4]} != true ]] || campaign_args+=(--dcgm)
[[ -z ${settings[5]} ]] || campaign_args+=(--device "${settings[5]}")
[[ -z ${settings[6]} ]] || campaign_args+=(--expected-sku "${settings[6]}")
echo 'Starting bounded H100 campaign; partial results are retained'
set +e
python3 "$source_dir/scripts/h100-campaign.py" "${campaign_args[@]}"
campaign_exit=$?
set -e
if [[ ! -f "$job_root/campaign/campaign.zip" ]]; then
  python3 "$source_dir/scripts/h100-campaign.py" --output "$job_root/campaign" --package-only --failure-reason campaign_interrupted
fi
stage=finished
exit "$campaign_exit"
