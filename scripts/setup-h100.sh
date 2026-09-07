#!/usr/bin/env bash
# Ubuntu H100 development-tool bootstrap. No driver, service, reboot, GPU load,
# reset, repository configuration or host security-policy changes.
# Functions are sourceable only for hermetic tests; sourcing performs no action.

setup_usage() {
  cat <<'EOF'
Usage: bash scripts/setup-h100.sh --prefix PRIVATE_DIR --output-env NEW_FILE
       [--install-system-deps] [--cuda-root EXISTING_DIR]
       [--budget-seconds 1800] [--dry-run]
Ubuntu 22.04/24.04 Linux x86-64 with an existing working NVIDIA driver.
Reuses validated tools or installs checksummed user-local Go 1.24.5, CMake
3.31.6 and CUDA 12.8.1 build/runtime/Compute Sanitizer components.
System build dependencies require explicit --install-system-deps and root or
passwordless sudo. Never prompts. Dry-run records a plan without compiler/driver execution,
network access or package installation. JSON status is NEW_FILE.json; a usable
sourceable NEW_FILE is published only after successful validation.
EOF
}

setup_json() {
  local value=$1
  value=${value//\\/\\\\}; value=${value//\"/\\\"}
  value=${value//$'\n'/\\n}; value=${value//$'\r'/\\r}; value=${value//$'\t'/\\t}
  printf '"%s"' "$value"
}

setup_log() { printf '%s\n' "$1" | tee -a "$setup_log_file"; }
setup_fail() { setup_status=$1; setup_message=$2; setup_log "$1: $2"; exit 1; }
setup_monotonic() { awk '{print int($1)}' /proc/uptime; }
setup_remaining() {
  local now
  now=$(setup_monotonic) || return 1
  printf '%s' "$((setup_deadline-now))"
}
setup_bounded() {
  local maximum=$1 remaining
  shift
  remaining=$(setup_remaining) || return 1
  ((remaining > 0)) || return 124
  ((maximum < remaining)) || maximum=$remaining
  timeout --signal=TERM --kill-after=5 "$maximum" env -i \
    PATH="$setup_system_path" LANG=C LC_ALL=C GOTOOLCHAIN=local \
    TMPDIR="$setup_temp" "$@"
}
setup_capture() { setup_bounded "$@" 2>/dev/null | head -c 4096; }
setup_step() {
  local label=$1 maximum=$2 code
  shift 2
  setup_log "Starting: $label"
  if setup_bounded "$maximum" "$@" >/dev/null 2>&1; then
    setup_log "Completed: $label"
  else
    code=$?
    if ((code == 124 || code == 137)); then
      setup_fail TIME_BUDGET_EXHAUSTED "$label exceeded its bounded allowance; incomplete files are retained."
    fi
    setup_fail TOOL_ERROR "$label failed (exit $code); no completion was inferred."
  fi
}

setup_platform() {
  [[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || return 1
  [[ -f /etc/os-release ]] || return 1
  local distro release
  distro=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
  release=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"')
  [[ "$distro" == ubuntu && ( "$release" == 22.04 || "$release" == 24.04 ) ]] || return 1
  setup_ubuntu=$release
}

setup_find_system() {
  local name=$1 directory
  for directory in /usr/local/bin /usr/bin /bin /usr/sbin /sbin; do
    if [[ -f "$directory/$name" && -x "$directory/$name" ]]; then printf '%s' "$directory/$name"; return 0; fi
  done
  return 1
}

setup_private_dir() {
  local directory=$1 owner mode
  [[ ! -L "$directory" ]] || return 1
  mkdir -p -m 700 -- "$directory" || return 1
  [[ -d "$directory" && ! -L "$directory" ]] || return 1
  owner=$(stat -c %u -- "$directory") || return 1
  mode=$(stat -c %a -- "$directory") || return 1
  [[ "$owner" == "$(id -u)" && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  (((8#$mode & 077) == 0))
}

setup_manifest() {
  [[ -n ${setup_manifest_file:-} && -n ${setup_attempt:-} ]] || return 0
  local tmp="$setup_attempt/status.json"
  {
    printf '{"schema_version":1,"status":'; setup_json "$setup_status"
    printf ',"message":'; setup_json "$setup_message"
    printf ',"setup_log":'; setup_json "$setup_log_file"
    printf ',"ubuntu_version":'; setup_json "${setup_ubuntu:-}"
    printf ',"go_version":'; setup_json "${setup_go_version:-}"
    printf ',"cmake_version":'; setup_json "${setup_cmake_version:-}"
    printf ',"cuda_release":'; setup_json "${setup_cuda_release:-}"
    printf ',"requested_versions":{"go":"1.24.5","cmake":"3.31.6","cuda":"12.8.1","nvcc":"12.8.93","cublas":"12.8.4.1"}'
    printf ',"go_bin":'; setup_json "${setup_go_bin:-}"
    printf ',"cmake_bin":'; setup_json "${setup_cmake_bin:-}"
    printf ',"cuda_root":'; setup_json "${setup_cuda:-}"
    printf ',"compute_sanitizer":'; setup_json "${setup_sanitizer:-}"
    printf ',"dcgm_status":'; setup_json "${setup_dcgm_status:-NOT_CHECKED}"
    printf ',"dcgm_installed_by_setup":false,"dcgm_note":"Optional DCGM requires an already installed 4.6.0 client and existing loopback hostengine; setup never installs or starts that service."'
    printf ',"system_dependencies_authorized":%s' "$setup_install"
    printf ',"driver_changed":false,"gpu_workload_executed":false,"hardware_qualified":false}\n'
  } > "$tmp"
  # The destination was reserved exclusively by this invocation.
  cp -- "$tmp" "$setup_manifest_file"
}

setup_finish() {
  local code=$?
  if [[ ${setup_status:-} == RUNNING ]]; then
    setup_status=TOOL_ERROR; setup_message='Setup stopped before validation completed; no environment was published.'
  fi
  setup_manifest || code=1
  return "$code"
}

setup_download() {
  local url=$1 digest=$2 maximum_bytes=$3 filename=$4 actual remaining
  [[ "$url" == https://* && "$digest" =~ ^[0-9a-f]{64}$ && "$filename" != */* ]] || setup_fail INTERNAL_ERROR 'Invalid pinned download specification.'
  setup_downloaded="$setup_prefix/downloads/$filename"
  if [[ -L "$setup_downloaded" || -L "$setup_downloaded.part" ]]; then setup_fail UNSAFE_PATH 'Download cache contains a symlink.'; fi
  if [[ -f "$setup_downloaded" ]]; then
    actual=$(sha256sum -- "$setup_downloaded"); actual=${actual%% *}
    if [[ "$actual" == "$digest" ]]; then setup_log "Reusing verified download: $filename"; return; fi
    setup_fail CHECKSUM_MISMATCH 'An existing cached download differs from its pinned SHA-256; it was not executed or overwritten.'
  fi
  remaining=$(setup_remaining)
  ((remaining > 0)) || setup_fail TIME_BUDGET_EXHAUSTED 'No setup budget remains for download.'
  setup_step "download $filename" "$remaining" "$setup_curl" --fail --silent --show-error \
    --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 20 --max-time "$remaining" --retry 2 --max-filesize "$maximum_bytes" \
    --output "$setup_downloaded.part" "$url"
  actual=$(sha256sum -- "$setup_downloaded.part"); actual=${actual%% *}
  [[ "$actual" == "$digest" ]] || setup_fail CHECKSUM_MISMATCH 'Downloaded bytes differ from the pinned SHA-256; extraction was refused.'
  mv -- "$setup_downloaded.part" "$setup_downloaded"
}

setup_extract() {
  local archive=$1 destination=$2
  mkdir -m 700 -- "$destination"
  # Only archives with pinned official digests reach this function. GNU tar's
  # traversal checks remain enabled; ownership and privileged modes are dropped.
  setup_step 'extract verified tool archive' 120 tar --extract --file "$archive" \
    --directory "$destination" --strip-components=1 --no-same-owner --no-same-permissions
}

setup_go_valid() {
  local candidate=$1 version
  [[ -x "$candidate" ]] || return 1
  version=$(setup_capture 10 "$candidate" version) || return 1
  [[ "$version" =~ ^go\ version\ go(1)\.([0-9]+)\.([0-9]+)\ linux/amd64$ ]] || return 1
  ((10#${BASH_REMATCH[2]} >= 24)) || return 1
  setup_go_version="1.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}"
  setup_go_bin=$(cd -- "$(dirname -- "$candidate")" && pwd -P)
}
setup_cmake_valid() {
  local candidate=$1 version major minor
  [[ -x "$candidate" && -x "$(dirname -- "$candidate")/ctest" ]] || return 1
  version=$(setup_capture 10 "$candidate" --version) || return 1
  [[ "$version" =~ ^cmake\ version\ ([0-9]+)\.([0-9]+)\.([0-9]+) ]] || return 1
  major=${BASH_REMATCH[1]}; minor=${BASH_REMATCH[2]}
  ((major > 3 || (major == 3 && minor >= 24))) || return 1
  setup_cmake_version="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}"
  setup_cmake_bin=$(cd -- "$(dirname -- "$candidate")" && pwd -P)
}

setup_cuda_valid() {
  local candidate=$1 version sanitizer macro expected
  [[ -x "$candidate/bin/nvcc" && -f "$candidate/include/cuda_runtime.h" && -f "$candidate/include/cublas_v2.h" && -f "$candidate/include/cublasLt.h" && -f "$candidate/lib64/libcudart.so" && -f "$candidate/lib64/libcublas.so" && -f "$candidate/lib64/libcublasLt.so" && -f "$candidate/nvvm/libdevice/libdevice.10.bc" ]] || return 1
  version=$(setup_capture 10 "$candidate/bin/nvcc" --version) || return 1
  [[ "$version" == *'release 12.8,'* && "$version" == *'V12.8.93'* ]] || return 1
  [[ -f "$candidate/include/cublas_api.h" ]] || return 1
  while read -r macro expected; do
    grep -Eq "^#define[[:space:]]+$macro[[:space:]]+$expected[[:space:]]*$" "$candidate/include/cublas_api.h" || return 1
  done <<'EOF'
CUBLAS_VER_MAJOR 12
CUBLAS_VER_MINOR 8
CUBLAS_VER_PATCH 4
CUBLAS_VER_BUILD 1
EOF
  sanitizer="$candidate/compute-sanitizer/compute-sanitizer"
  [[ -x "$sanitizer" ]] || sanitizer="$candidate/bin/compute-sanitizer"
  [[ -x "$sanitizer" ]] || return 1
  version=$(setup_capture 10 "$sanitizer" --version) || return 1
  [[ "$version" == *'2025.1.1'* || "$version" == *'12.8.93'* ]] || return 1
  setup_cuda=$(cd -- "$candidate" && pwd -P)
  setup_cuda_release=12.8.1
  setup_sanitizer="$setup_cuda/${sanitizer#"$candidate/"}"
}

setup_install_cuda() {
  local stage="$setup_attempt/cuda-stage" name version digest size archive part
  mkdir -m 700 -- "$stage"
  # Pinned from NVIDIA redistrib_12.8.1.json (2025-03-06). No driver package.
  while read -r name version digest size; do
    archive="$name-linux-x86_64-$version-archive.tar.xz"
    setup_download "https://developer.download.nvidia.com/compute/cuda/redist/$name/linux-x86_64/$archive" "$digest" "$size" "$archive"
    part="$setup_attempt/component-$name"
    setup_extract "$setup_downloaded" "$part"
    setup_step "assemble $name" 120 cp -a -- "$part/." "$stage/"
    mkdir -p -m 700 -- "$stage/licenses/$name"
    if [[ -f "$part/LICENSE" ]]; then cp -- "$part/LICENSE" "$stage/licenses/$name/"; fi
    if [[ -f "$part/LICENSE.txt" ]]; then cp -- "$part/LICENSE.txt" "$stage/licenses/$name/"; fi
  done <<'EOF'
cuda_cccl 12.8.90 0740e9e01e4f15e17c5ab8d68bba4f8ec0eb6b84edccba4ac45112d2d2174e4b 928524
cuda_cudart 12.8.90 8d566b5fe745c46842dc16945cf36686227536decd2302c372be86da37faca68 1354240
cuda_nvcc 12.8.93 9961b3484b6b71314063709a4f9529654f96782ad39e72bf1e00f070db8210d3 79015464
cuda_sanitizer_api 12.8.93 ae3574f052c0e06c95305962668eb1fe6ab571dfbb58b305fdb14d523bb1b240 9940020
libcublas 12.8.4.1 21718957c2cf000bacd69d36c95708a2319199e39e056f8b4f0f68e3b9f323bb 938651324
EOF
  if [[ -d "$stage/lib" && ! -e "$stage/lib64" ]]; then ln -s lib "$stage/lib64"; fi
  if [[ ! -e "$stage/bin/compute-sanitizer" ]]; then ln -s ../compute-sanitizer/compute-sanitizer "$stage/bin/compute-sanitizer"; fi
  setup_cuda_valid "$stage" || setup_fail VALIDATION_FAILED 'The assembled CUDA components did not validate; staging is retained.'
  [[ ! -e "$setup_prefix/cuda-12.8.1" && ! -L "$setup_prefix/cuda-12.8.1" ]] || setup_fail UNSAFE_PATH 'An incomplete CUDA destination already exists; it was not overwritten.'
  mv -- "$stage" "$setup_prefix/cuda-12.8.1"
  setup_cuda_valid "$setup_prefix/cuda-12.8.1" || setup_fail VALIDATION_FAILED 'Relocated CUDA tools did not validate.'
}

setup_system_dependencies() {
  local tool path missing=() privilege=()
  for tool in gcc g++ cc c++ make readelf ldd git curl tar xz sha256sum; do
    if ! setup_find_system "$tool" >/dev/null; then missing+=("$tool"); fi
  done
  if ((${#missing[@]})); then
    [[ "$setup_install" == true ]] || setup_fail DEPENDENCY_MISSING 'System build/download dependencies are missing; --install-system-deps was not authorized.'
    if ((EUID != 0)); then
      path=$(setup_find_system sudo) || setup_fail PERMISSION_DENIED 'Root or passwordless sudo is required for the authorized package operation.'
      setup_bounded 5 "$path" -n true >/dev/null 2>&1 || setup_fail PERMISSION_DENIED 'Passwordless sudo is unavailable; no password prompt was attempted.'
      privilege=("$path" -n)
    fi
    path=$(setup_find_system apt-get) || setup_fail DEPENDENCY_MISSING 'The supported apt-get package manager is missing.'
    setup_step 'refresh existing signed Ubuntu package indexes' 300 "${privilege[@]}" env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l \
      "$path" -o DPkg::Lock::Timeout=30 -o Acquire::Retries=1 update
    setup_step 'install system build dependencies' 600 "${privilege[@]}" env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l \
      "$path" -y --no-install-recommends --no-upgrade --no-remove -o DPkg::Lock::Timeout=30 \
      -o Dpkg::Options::=--force-confold install build-essential binutils git curl ca-certificates xz-utils
    for tool in gcc g++ cc c++ make readelf ldd git curl tar xz sha256sum; do
      setup_find_system "$tool" >/dev/null || setup_fail DEPENDENCY_MISSING 'A required system tool remains unavailable after package installation.'
    done
  fi
  setup_curl=$(setup_find_system curl)
}

setup_validate_build() {
  local version
  version=$(setup_capture 10 /usr/bin/g++ -dumpfullversion) || setup_fail VALIDATION_FAILED 'The system C++ compiler could not report its version.'
  [[ "$version" =~ ^([0-9]+)\. ]] && ((BASH_REMATCH[1] >= 6 && BASH_REMATCH[1] <= 14)) || setup_fail UNSUPPORTED 'CUDA 12.8 requires a supported GCC major version (6 through 14).'
  cat > "$setup_attempt/toolchain-check.cu" <<'EOF'
#include <cuda_runtime.h>
#include <cublas_v2.h>
#include <cublasLt.h>
int main() {
  int runtime_version = 0;
  auto volatile blas_version = &cublasGetVersion_v2;
  auto volatile lt_version = &cublasLtGetVersion;
  if (!blas_version || !lt_version) return 3;
  if (cudaRuntimeGetVersion(&runtime_version) != cudaSuccess) return 1;
  return runtime_version == 12080 ? 0 : 2;
}
EOF
  # Compile/link only: no executable, CUDA context or kernel is run by setup.
  setup_step 'compile and link CUDA 12.8 build prerequisites (no execution)' 120 \
    "$setup_cuda/bin/nvcc" -std=c++17 -arch=sm_90 --cudart shared \
    "$setup_attempt/toolchain-check.cu" -L "$setup_cuda/lib64" -lcublas -lcublasLt \
    -o "$setup_attempt/toolchain-check"
}

setup_probe_dcgm() {
  local tool version builds matches
  setup_dcgm_status=DEPENDENCY_MISSING
  if ! tool=$(setup_find_system dcgmi); then
    setup_log 'Optional DCGM is absent; it was not installed and its campaign attempt remains an explicit dependency gap.'
    return
  fi
  setup_dcgm_status=UNSUPPORTED
  version=$(setup_capture 8 "$tool" --version) || { setup_log 'Optional installed DCGM version could not be verified.'; return; }
  [[ "$version" =~ [Vv]ersion[[:space:]]*:[[:space:]]*4\.6\.0[[:space:]]*$ ]] || { setup_log 'Optional installed DCGM is outside the pinned 4.6.0 adapter.'; return; }
  setup_dcgm_status=SERVICE_UNAVAILABLE
  builds=$(setup_capture 8 "$tool" --vv --host 127.0.0.1) || { setup_log 'Optional existing loopback DCGM hostengine was unavailable; no service was started.'; return; }
  matches=$(printf '%s\n' "$builds" | grep -Ec '^Version[[:space:]]*:[[:space:]]*4\.6\.0[[:space:]]*$' || true)
  if [[ "$matches" == 2 && "$builds" == *'Local build info:'* && "$builds" == *'Hostengine build info:'* ]]; then
    setup_dcgm_status=AVAILABLE
    setup_log 'Existing optional DCGM client and loopback hostengine report 4.6.0; selected-device campaign admission is still required.'
  else
    setup_log 'Optional loopback DCGM hostengine version could not be admitted; no service configuration was changed.'
  fi
}
setup_main() {
  set -Eeuo pipefail
  umask 077
  setup_prefix=; setup_output=; setup_requested_cuda=; setup_install=false; setup_dry=false
  setup_budget=1800; setup_status=RUNNING; setup_message='Setup is running.'
  setup_system_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  while (($#)); do
    case "$1" in
      --help|-h) setup_usage; return 0 ;;
      --install-system-deps) setup_install=true; shift ;;
      --dry-run) setup_dry=true; shift ;;
      --prefix|--output-env|--cuda-root|--budget-seconds)
        (($# >= 2)) || { setup_usage >&2; return 1; }
        case "$1" in --prefix) setup_prefix=$2;; --output-env) setup_output=$2;; --cuda-root) setup_requested_cuda=$2;; --budget-seconds) setup_budget=$2;; esac
        shift 2 ;;
      *) setup_usage >&2; return 1 ;;
    esac
  done
  [[ -n "$setup_prefix" && -n "$setup_output" && "$setup_budget" =~ ^[0-9]{1,4}$ ]] || { setup_usage >&2; return 1; }
  ((10#$setup_budget >= 30 && 10#$setup_budget <= 3600)) || { echo 'Setup budget must be 30–3600 seconds.' >&2; return 1; }
  [[ "$setup_prefix$setup_output$setup_requested_cuda" != *[$'\001'-$'\037'$'\177']* ]] || { echo 'Control characters are not accepted in setup paths.' >&2; return 1; }
  setup_private_dir "$setup_prefix" || { echo 'Prefix must be an owned private directory without a final symlink.' >&2; return 1; }
  setup_prefix=$(cd -- "$setup_prefix" && pwd -P)
  [[ "$setup_prefix" != / ]] || return 1
  setup_private_dir "$(dirname -- "$setup_output")" || { echo 'Environment parent must be an owned private directory.' >&2; return 1; }
  setup_output="$(cd -- "$(dirname -- "$setup_output")" && pwd -P)/$(basename -- "$setup_output")"
  [[ ! -e "$setup_output" && ! -L "$setup_output" && ! -e "$setup_output.json" && ! -L "$setup_output.json" ]] || { echo 'Environment/status destinations must be new; prior attempts are preserved.' >&2; return 1; }
  setup_attempt=$(mktemp -d "$setup_prefix/attempt-XXXXXXXX")
  setup_log_file="$setup_attempt/setup.log"; : > "$setup_log_file"
  setup_manifest_file="$setup_output.json"
  (set -o noclobber; : > "$setup_manifest_file") || return 1
  trap setup_finish EXIT
  trap 'setup_status=CANCELLED; setup_message="Setup interrupted; incomplete files are retained and no environment was published."; exit 130' INT TERM
  setup_temp="$setup_prefix/tmp"
  setup_private_dir "$setup_temp" || setup_fail UNSAFE_PATH 'Setup temporary directory is not private.'
  setup_private_dir "$setup_prefix/downloads" || setup_fail UNSAFE_PATH 'Setup download directory is not private.'
  setup_platform || setup_fail UNSUPPORTED 'Setup supports native Ubuntu 22.04/24.04 Linux x86-64 only.'
  setup_deadline=$(($(setup_monotonic)+10#$setup_budget))
  setup_log 'Platform accepted; driver/settings/services are preserved.'
  if [[ "$setup_dry" == true ]]; then
    setup_status=DRY_RUN; setup_message='Plan only: validate existing NVIDIA driver and tools; reuse or install pinned user-local tools; system packages only if explicitly authorized. No compiler/driver execution, network, package installation or hardware qualification occurred.'
    setup_log "$setup_message"
    return 0
  fi
  command -v timeout >/dev/null || setup_fail DEPENDENCY_MISSING 'GNU timeout is required to bound setup.'
  local smi versions candidate found=false free_kib
  smi=$(setup_find_system nvidia-smi) || setup_fail DRIVER_UNAVAILABLE 'An existing system nvidia-smi is required; setup never installs a driver.'
  versions=$(setup_capture 8 "$smi" --query-gpu=driver_version --format=csv,noheader) || setup_fail DRIVER_UNAVAILABLE 'The existing NVIDIA driver query failed; setup did not change it.'
  [[ "$versions" =~ [0-9]+\.[0-9]+ ]] || setup_fail DRIVER_UNAVAILABLE 'The existing NVIDIA driver did not report a usable version.'
  setup_system_dependencies
  for candidate in "$setup_prefix/go-1.24.5/bin/go" /usr/local/go/bin/go /usr/local/bin/go /usr/bin/go; do
    if setup_go_valid "$candidate"; then found=true; break; fi
  done
  if [[ "$found" == false ]]; then
    setup_download https://go.dev/dl/go1.24.5.linux-amd64.tar.gz 10ad9e86233e74c0f6590fe5426895de6bf388964210eac34a6d83f38918ecdc 100000000 go1.24.5.linux-amd64.tar.gz
    setup_extract "$setup_downloaded" "$setup_attempt/go-stage"
    setup_go_valid "$setup_attempt/go-stage/bin/go" || setup_fail VALIDATION_FAILED 'Downloaded Go toolchain did not validate.'
    [[ ! -e "$setup_prefix/go-1.24.5" && ! -L "$setup_prefix/go-1.24.5" ]] || setup_fail UNSAFE_PATH 'Existing incomplete Go directory was preserved.'
    mv -- "$setup_attempt/go-stage" "$setup_prefix/go-1.24.5"
    setup_go_valid "$setup_prefix/go-1.24.5/bin/go" || setup_fail VALIDATION_FAILED 'Relocated Go toolchain did not validate.'
  fi
  found=false
  for candidate in "$setup_prefix/cmake-3.31.6/bin/cmake" /usr/local/bin/cmake /usr/bin/cmake; do
    if setup_cmake_valid "$candidate"; then found=true; break; fi
  done
  if [[ "$found" == false ]]; then
    setup_download https://github.com/Kitware/CMake/releases/download/v3.31.6/cmake-3.31.6-linux-x86_64.tar.gz 5a1133ff103c71eb5120e2cc3de922733e7d8a26a98ae716397e8676adb367bf 100000000 cmake-3.31.6-linux-x86_64.tar.gz
    setup_extract "$setup_downloaded" "$setup_attempt/cmake-stage"
    setup_cmake_valid "$setup_attempt/cmake-stage/bin/cmake" || setup_fail VALIDATION_FAILED 'Downloaded CMake toolchain did not validate.'
    [[ ! -e "$setup_prefix/cmake-3.31.6" && ! -L "$setup_prefix/cmake-3.31.6" ]] || setup_fail UNSAFE_PATH 'Existing incomplete CMake directory was preserved.'
    mv -- "$setup_attempt/cmake-stage" "$setup_prefix/cmake-3.31.6"
    setup_cmake_valid "$setup_prefix/cmake-3.31.6/bin/cmake" || setup_fail VALIDATION_FAILED 'Relocated CMake toolchain did not validate.'
  fi
  if [[ -n "$setup_requested_cuda" ]]; then
    setup_cuda_valid "$setup_requested_cuda" || setup_fail VALIDATION_FAILED 'Explicit CUDA root must provide complete CUDA 12.8.1 / nvcc 12.8.93 / Compute Sanitizer components.'
  else
    found=false
    for candidate in "$setup_prefix/cuda-12.8.1" /usr/local/cuda-12.8 /usr/local/cuda; do
      if setup_cuda_valid "$candidate"; then found=true; break; fi
    done
    if [[ "$found" == false ]]; then
      free_kib=$(df -Pk -- "$setup_prefix" | awk 'NR==2 {print $4}')
      [[ "$free_kib" =~ ^[0-9]+$ ]] && ((free_kib >= 8388608)) || setup_fail INSUFFICIENT_SPACE 'At least 8 GiB free is required for retained CUDA downloads, staging and build tools.'
      setup_install_cuda
    fi
  fi
  setup_validate_build
  setup_probe_dcgm
  (($(setup_remaining) > 0)) || setup_fail TIME_BUDGET_EXHAUSTED 'Setup completed too late to publish a validated environment within its budget.'
  local staged_env="$setup_attempt/environment.sh"
  {
    printf '# Generated only after toolchain validation; no hardware qualification.\n'
    printf 'export PATH=%q\n' "$setup_go_bin:$setup_cmake_bin:$setup_cuda/bin:$setup_system_path"
    printf 'export CUDA_ROOT=%q\nexport CUDAToolkit_ROOT=%q\n' "$setup_cuda" "$setup_cuda"
    printf 'export CUDACXX=%q\nexport GOTOOLCHAIN=local\nexport TMPDIR=%q\n' "$setup_cuda/bin/nvcc" "$setup_temp"
  } > "$staged_env"
  # noclobber protects against accidental reuse/races; the parent is private.
  (set -o noclobber; cat -- "$staged_env" > "$setup_output") || setup_fail UNSAFE_PATH 'Environment destination appeared during setup; it was not overwritten.'
  setup_status=READY; setup_message='Pinned/reused tools passed version, component and compile/link checks. No GPU workload or hardware qualification was performed.'
  setup_log "$setup_message"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then setup_main "$@"; fi
