#!/usr/bin/env bash
# Hermetic detached-wrapper fixtures. Fake setup and campaign programs perform
# only local file writes; the actual remote wrapper is exercised unchanged.
set -Eeuo pipefail
umask 077
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
if [[ -x "$repo_dir/build/.toolchains/python-3.13.12/python.exe" ]]; then
  fixture_python="$repo_dir/build/.toolchains/python-3.13.12/python.exe"
else
  fixture_python=$(command -v python3)
fi
export fixture_python
# Native Windows Python writes CRLF stdout; Linux mapfile semantics need LF.
python3() { "$fixture_python" "$@" | tr -d '\r'; }
export -f python3

run_case() {
  local scenario=$1 expected=$2 job_id job_root code
  job_id="gri-h100-$(python3 -c 'import secrets; print(secrets.token_hex(12))')"
  job_root="/tmp/$job_id"
  [[ "$job_root" =~ ^/tmp/gri-h100-[0-9a-f]{24}$ && ! -e "$job_root" && ! -L "$job_root" ]]
  mkdir -m 700 -- "$job_root"
  printf '%s\n' "$job_id" > "$job_root/owner-marker"
  printf '%s\n' "$scenario" > "$job_root/fixture-case"
  mkdir -p -m 700 -- "$job_root/source/scripts"
  python3 - "$job_root/node-config.json" "$scenario" <<'PY'
import json,pathlib,sys
scenario=sys.argv[2]
enabled=scenario!='disabled'
config=dict(setup_budget_seconds=60,campaign_budget_seconds=120,
            install_system_deps=enabled,sanitizer=enabled,dcgm=enabled,
            device='GPU-12345678-1234-1234-1234-1234567890ab' if enabled else '',
            expected_sku='h100-sxm-80gb' if enabled else '',
            cuda_root='/fixture/cuda toolkit' if enabled else '')
if scenario=='invalid-config': config['setup_budget_seconds']='invalid'
pathlib.Path(sys.argv[1]).write_text(json.dumps(config),encoding='utf-8')
PY
  cat > "$job_root/source/scripts/setup-h100.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
job_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
scenario=$(cat "$job_root/fixture-case")
printf '%s\n' "$@" > "$job_root/setup-args"
mkdir -p -m 700 -- "$job_root/toolchain/attempt-fixture"
log_path="$job_root/toolchain/attempt-fixture/setup.log"
printf 'Normalized fixture setup status\n' > "$log_path"
if [[ "$scenario" == outside-log ]]; then
  log_path="$job_root/outside-secret"
  printf 'SECRET_MUST_NOT_ENTER_REPORT\n' > "$log_path"
fi
if [[ "$scenario" != missing-status ]]; then
  python3 - "$job_root/setup.env.json" "$log_path" <<'PY'
import json,pathlib,sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({'schema_version':1,'setup_log':sys.argv[2],'release_qualified':False}),encoding='utf-8')
PY
fi
printf "export CUDA_ROOT='/fixture/cuda toolkit'\n" > "$job_root/setup.env"
[[ "$scenario" != setup-failed && "$scenario" != missing-status ]] || exit 3
SH
  cat > "$job_root/source/scripts/h100-campaign.py" <<'PY'
import hashlib,json,pathlib,sys,zipfile
root=pathlib.Path(__file__).resolve().parents[2]
scenario=(root/'fixture-case').read_text().strip()
args=sys.argv[1:]
with (root/'campaign-calls.jsonl').open('a',encoding='utf-8') as stream:
    stream.write(json.dumps(args)+'\n')
output=pathlib.Path(args[args.index('--output')+1])
output.mkdir(parents=True,exist_ok=True)
if '--package-only' not in args and scenario=='campaign-interrupted':
    (output/'partial-evidence.json').write_text('{"release_qualified":false}',encoding='utf-8')
    raise SystemExit(7)
reason=args[args.index('--failure-reason')+1] if '--failure-reason' in args else ''
with zipfile.ZipFile(output/'campaign.zip','w') as archive:
    archive.writestr('campaign.json',json.dumps({'failure_reason':reason,'release_qualified':False}))
digest=hashlib.sha256((output/'campaign.zip').read_bytes()).hexdigest()
(output/'campaign.zip.sha256').write_text(digest+'  campaign.zip\n',encoding='ascii')
PY
  set +e
  # The outer timeout bounds even a wrapper regression; fixtures invoke no GPU.
  timeout --kill-after=2s 20s bash "$repo_dir/scripts/remote-h100-job.sh" "$job_root" > "$job_root/fixture-output.log" 2>&1
  code=$?
  set -e
  if [[ "$code" != "$expected" ]]; then
    cat -- "$job_root/fixture-output.log" >&2
    printf 'FAIL wrapper %s: exit %s, expected %s\n' "$scenario" "$code" "$expected" >&2
    return 1
  fi
  python3 - "$job_root" "$scenario" "$expected" <<'PY'
import hashlib,json,pathlib,sys,zipfile
root=pathlib.Path(sys.argv[1]).resolve()
scenario=sys.argv[2]
finish=json.loads((root/'job-finished.json').read_text(encoding='utf-8'))
assert finish['job_exit_code']==int(sys.argv[3]),finish
assert finish['release_qualified'] is False,finish
assert not (root/'job-finished.json.tmp').exists()
if scenario=='invalid-config':
    assert finish['stage']=='setup',finish
    assert not (root/'setup-args').exists()
    assert not (root/'campaign-calls.jsonl').exists()
else:
    setup_args=(root/'setup-args').read_text(encoding='utf-8').splitlines()
    assert setup_args[setup_args.index('--budget-seconds')+1]=='60',setup_args
    assert ('--install-system-deps' in setup_args)==(scenario!='disabled'),setup_args
    if scenario!='disabled': assert setup_args[setup_args.index('--cuda-root')+1]=='/fixture/cuda toolkit',setup_args
    calls=[json.loads(line) for line in (root/'campaign-calls.jsonl').read_text(encoding='utf-8').splitlines()]
    setup_failed=scenario in ('setup-failed','missing-status')
    assert finish['stage']==('setup_failed' if setup_failed else 'finished'),finish
    assert len(calls)==(2 if scenario=='campaign-interrupted' else 1),calls
    if setup_failed:
        assert '--package-only' in calls[0],calls
        assert calls[0][calls[0].index('--failure-reason')+1]=='setup_failed',calls
        assert (root/'campaign/logs/setup.log').is_file()
    else:
        args=calls[0]
        assert '--package-only' not in args,args
        assert args[args.index('--total-budget-seconds')+1]=='120',args
        assert ('--sanitizer' in args)==(scenario!='disabled'),args
        assert ('--dcgm' in args)==(scenario!='disabled'),args
        if scenario!='disabled': assert args[args.index('--device')+1]=='GPU-12345678-1234-1234-1234-1234567890ab',args
        if scenario=='campaign-interrupted':
            assert calls[1][calls[1].index('--failure-reason')+1]=='campaign_interrupted',calls
            assert (root/'campaign/partial-evidence.json').is_file()
    summary=(root/'setup-summary.log').read_text(encoding='utf-8')
    assert 'SECRET_MUST_NOT_ENTER_REPORT' not in summary,summary
    if scenario=='outside-log': assert 'unavailable' in summary,summary
    if scenario=='missing-status': assert 'did not publish' in summary,summary
    archive=root/'campaign/campaign.zip'
    checksum=(root/'campaign/campaign.zip.sha256').read_text(encoding='ascii').split()[0]
    assert hashlib.sha256(archive.read_bytes()).hexdigest()==checksum
    with zipfile.ZipFile(archive) as source:
        report=json.loads(source.read('campaign.json'))
        assert report['release_qualified'] is False
        expected_reason='setup_failed' if setup_failed else 'campaign_interrupted' if scenario=='campaign-interrupted' else ''
        assert report['failure_reason']==expected_reason,report
print('PASS wrapper '+scenario)
# Remove only this newly created fixture after verifying its resolved directory,
# exact ownership marker and fixture marker. No parent or computed glob deletion.
import re,shutil
assert re.fullmatch(r'gri-h100-[0-9a-f]{24}',root.name)
assert (root/'owner-marker').read_text().strip()==root.name
assert (root/'fixture-case').read_text().strip()==scenario
assert not pathlib.Path(sys.argv[1]).is_symlink()
shutil.rmtree(root)
PY
}

run_case success 0
run_case disabled 0
run_case setup-failed 2
run_case missing-status 2
run_case campaign-interrupted 7
run_case outside-log 0
run_case invalid-config 1
printf 'All detached H100 wrapper fixtures passed; no network or GPU was used.\n'
