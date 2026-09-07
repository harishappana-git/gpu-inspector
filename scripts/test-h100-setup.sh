#!/usr/bin/env bash
# Hermetic setup tests: no network, apt, NVIDIA driver or compiler execution.
# Works with Git Bash on Windows; all platform/tool effects are fixture functions.
set -Eeuo pipefail
umask 077
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
mkdir -p -- "$repo_dir/build"
fixture_dir=$(mktemp -d "$repo_dir/build/h100-setup-fixture.XXXXXXXX")

run_setup_case() {
  local name=$1 expected=$2 scenario=$3 output="$fixture_dir/$1/setup env.sh" code
  mkdir -p -m 700 -- "$(dirname -- "$output")"
  set +e
  (
    source "$repo_dir/scripts/setup-h100.sh"
    setup_private_dir() { [[ ! -L "$1" ]] && mkdir -p -m 700 -- "$1"; }
    setup_platform() { [[ "$scenario" != unsupported ]] || return 1; setup_ubuntu=22.04; }
    setup_monotonic() { printf 10; }
    setup_find_system() {
      [[ "$scenario" != driver-missing || "$1" != nvidia-smi ]] || return 1
      printf '/fixture/%s' "$1"
    }
    setup_capture() {
      printf '%s\n' "$*" >> "$fixture_dir/$name/tool-calls"
      [[ "$scenario" != driver-failed ]] || return 1
      printf '570.124.06\n'
    }
    setup_system_dependencies() {
      [[ "$scenario" != deps-missing ]] || setup_fail DEPENDENCY_MISSING 'Fixture dependencies are missing.'
    }
    setup_go_valid() { setup_go_bin="$setup_prefix/go tools/bin"; setup_go_version=1.24.5; }
    setup_cmake_valid() { setup_cmake_bin="$setup_prefix/cmake tools/bin"; setup_cmake_version=3.31.6; }
    setup_cuda_valid() {
      [[ "$scenario" != cuda-invalid ]] || return 1
      setup_cuda="$setup_prefix/cuda tools"; setup_cuda_release=12.8.1
      setup_sanitizer="$setup_cuda/compute-sanitizer/compute-sanitizer"
    }
    setup_validate_build() {
      [[ "$scenario" != compile-failed ]] || setup_fail VALIDATION_FAILED 'Fixture compile/link failed.'
      printf 'compile-only; no executable run\n' >> "$fixture_dir/$name/tool-calls"
    }
    setup_probe_dcgm() { setup_dcgm_status=DEPENDENCY_MISSING; }
    setup_download() { echo 'Unexpected download attempted in hermetic fixture' >&2; exit 90; }
    setup_install_cuda() { echo 'Unexpected installation attempted in hermetic fixture' >&2; exit 91; }
    args=(--prefix "$fixture_dir/$name/private tools" --output-env "$output" --cuda-root '/fixture/explicit cuda')
    [[ "$scenario" != dry ]] || args+=(--dry-run)
    setup_main "${args[@]}"
  ) > "$fixture_dir/$name/terminal.log" 2>&1
  code=$?
  set -e
  [[ -f "$output.json" ]] || { echo "$name missing status manifest" >&2; return 1; }
  grep -Fq '"status":"'"$expected"'"' "$output.json" || { cat "$output.json"; return 1; }
  if [[ "$expected" == READY ]]; then
    [[ "$code" == 0 && -f "$output" ]] || return 1
    (
      source "$output"
      [[ "$CUDA_ROOT" == "$fixture_dir/$name/private tools/cuda tools" && "$GOTOOLCHAIN" == local && "$TMPDIR" == "$fixture_dir/$name/private tools/tmp" ]] || exit 1
      [[ "$PATH" != *SECRET_ENVIRONMENT* ]] || exit 1
    )
  else
    [[ ! -e "$output" ]] || { echo 'Failure/plan published a usable environment' >&2; return 1; }
    [[ "$expected" == DRY_RUN || "$code" != 0 ]] || return 1
  fi
  if [[ "$scenario" == dry ]]; then [[ ! -e "$fixture_dir/$name/tool-calls" ]] || return 1; fi
  ! grep -Rq 'PRIVATE_CREDENTIAL_MARKER' "$fixture_dir/$name" || { echo 'Environment leaked into setup artifacts' >&2; return 1; }
}

export SECRET_ENVIRONMENT=PRIVATE_CREDENTIAL_MARKER
run_setup_case reused READY ready
run_setup_case plan DRY_RUN dry
run_setup_case unsupported UNSUPPORTED unsupported
run_setup_case no-driver DRIVER_UNAVAILABLE driver-missing
run_setup_case bad-driver DRIVER_UNAVAILABLE driver-failed
run_setup_case no-dependencies DEPENDENCY_MISSING deps-missing
run_setup_case bad-cuda VALIDATION_FAILED cuda-invalid
run_setup_case bad-compile VALIDATION_FAILED compile-failed

# Validate actual version parsing against fixture executables, independently of
# the full workflow mocks above.
(
  source "$repo_dir/scripts/setup-h100.sh"
  setup_prefix="$fixture_dir/validators"
  root="$setup_prefix/cuda"
  mkdir -p "$root/bin" "$root/include" "$root/lib64" "$root/nvvm/libdevice" "$root/compute-sanitizer" "$setup_prefix/go/bin" "$setup_prefix/cmake/bin"
  for file in bin/nvcc include/cuda_runtime.h include/cublas_v2.h include/cublasLt.h lib64/libcudart.so lib64/libcublas.so lib64/libcublasLt.so nvvm/libdevice/libdevice.10.bc compute-sanitizer/compute-sanitizer; do : > "$root/$file"; done
  : > "$setup_prefix/go/bin/go"; : > "$setup_prefix/cmake/bin/cmake"; : > "$setup_prefix/cmake/bin/ctest"
  for file in "$root/bin/nvcc" "$root/compute-sanitizer/compute-sanitizer" "$setup_prefix/go/bin/go" "$setup_prefix/cmake/bin/cmake" "$setup_prefix/cmake/bin/ctest"; do
    printf '#!/bin/sh\nexit 99\n' > "$file"
  done
  chmod 700 "$root/bin/nvcc" "$root/compute-sanitizer/compute-sanitizer" "$setup_prefix/go/bin/go" "$setup_prefix/cmake/bin/cmake" "$setup_prefix/cmake/bin/ctest"
  printf '#define CUBLAS_VER_MAJOR 12\n#define CUBLAS_VER_MINOR 8\n#define CUBLAS_VER_PATCH 4\n#define CUBLAS_VER_BUILD 1\n' > "$root/include/cublas_api.h"
  fixture_nvcc=12.8.93; fixture_go=1.24.5; fixture_cmake=3.31.6
  setup_capture() {
    case "$2" in
      */nvcc) printf 'Cuda compilation tools, release 12.8, V%s\n' "$fixture_nvcc" ;;
      */compute-sanitizer) printf 'Compute Sanitizer version 2025.1.1\n' ;;
      */go) printf 'go version go%s linux/amd64\n' "$fixture_go" ;;
      */cmake) printf 'cmake version %s\n' "$fixture_cmake" ;;
      *) exit 92 ;;
    esac
  }
  setup_cuda_valid "$root"
  setup_go_valid "$setup_prefix/go/bin/go"
  setup_cmake_valid "$setup_prefix/cmake/bin/cmake"
  fixture_nvcc=12.8.61
  if setup_cuda_valid "$root"; then echo 'Wrong CUDA update accepted' >&2; exit 1; fi
  fixture_go=1.23.9
  if setup_go_valid "$setup_prefix/go/bin/go"; then echo 'Old Go accepted' >&2; exit 1; fi
  fixture_cmake=3.22.1
  if setup_cmake_valid "$setup_prefix/cmake/bin/cmake"; then echo 'Ubuntu 22.04 old CMake accepted' >&2; exit 1; fi
  fixture_nvcc=12.8.93
  printf '#define CUBLAS_VER_MAJOR 11\n' > "$root/include/cublas_api.h"
  if setup_cuda_valid "$root"; then echo 'Mismatched cuBLAS accepted' >&2; exit 1; fi
)

# Digest admission: a cached mismatch cannot reach extraction/download and a
# matching cached object is reused without network access.
(
  source "$repo_dir/scripts/setup-h100.sh"
  setup_prefix="$fixture_dir/cache-test"; setup_log_file="$fixture_dir/cache.log"
  mkdir -p "$setup_prefix/downloads"
  printf 'synthetic pinned bytes\n' > "$setup_prefix/downloads/fixture.tar.xz"
  digest=$(sha256sum "$setup_prefix/downloads/fixture.tar.xz"); digest=${digest%% *}
  setup_step() { echo 'Cached fixture unexpectedly ran a command' >&2; exit 93; }
  setup_download https://developer.download.nvidia.com/fixture "$digest" 1000 fixture.tar.xz
  if (setup_download https://developer.download.nvidia.com/fixture 0000000000000000000000000000000000000000000000000000000000000000 1000 fixture.tar.xz); then exit 1; fi
  setup_remaining() { printf 30; }
  setup_curl=/fixture/curl
  setup_step() { printf 'synthetic pinned bytes\n' > "$setup_downloaded.part"; }
  setup_download https://developer.download.nvidia.com/fixture "$digest" 1000 new-fixture.tar.xz
  [[ -f "$setup_prefix/downloads/new-fixture.tar.xz" ]] || exit 1
  if (setup_download https://developer.download.nvidia.com/fixture 0000000000000000000000000000000000000000000000000000000000000000 1000 bad-fixture.tar.xz); then exit 1; fi
  [[ ! -e "$setup_prefix/downloads/bad-fixture.tar.xz" ]] || exit 1
)

(
  source "$repo_dir/scripts/setup-h100.sh"
  setup_log_file="$fixture_dir/dcgm.log"
  setup_find_system() { return 1; }
  setup_probe_dcgm
  [[ "$setup_dcgm_status" == DEPENDENCY_MISSING ]] || exit 1
  setup_find_system() { printf /fixture/dcgmi; }
  setup_capture() {
    case "$3" in
      --version) printf 'dcgmi version: 4.6.0\n' ;;
      --vv) [[ "$4" == --host && "$5" == 127.0.0.1 ]] || exit 97; printf 'Local build info:\nVersion : 4.6.0\nHostengine build info:\nVersion : 4.6.0\n' ;;
      *) exit 98 ;;
    esac
  }
  setup_probe_dcgm
  [[ "$setup_dcgm_status" == AVAILABLE ]] || exit 1
)

# The real apt decision logic is tested with non-executing command/privilege
# fixtures. No fixture can enter a real apt, sudo, download or driver command.
(
  source "$repo_dir/scripts/setup-h100.sh"
  setup_log_file="$fixture_dir/apt.log"; setup_install=false; installed=false
  setup_find_system() {
    [[ "$1" != gcc || "$installed" == true ]] || return 1
    printf '/fixture/%s' "$1"
  }
  setup_bounded() { [[ "$*" == *' -n true'* ]] || { echo 'Unexpected privilege fixture' >&2; exit 94; }; }
  setup_step() {
    printf '%s\n' "$*" >> "$fixture_dir/apt-calls"
    [[ "$*" != *--allow-unauthenticated* && "$*" != *nvidia* && "$*" != *cuda-* && "$*" != *' upgrade'* ]] || { echo 'Forbidden package action' >&2; exit 95; }
    if [[ "$1" == 'install system build dependencies' ]]; then
      [[ "$*" == *DEBIAN_FRONTEND=noninteractive* && "$*" == *--no-remove* && "$*" == *DPkg::Lock::Timeout=30* ]] || exit 96
      installed=true
    fi
  }
  if (setup_system_dependencies); then echo 'Missing apt opt-in ignored' >&2; exit 1; fi
  [[ ! -e "$fixture_dir/apt-calls" ]] || exit 1
  setup_install=true
  setup_system_dependencies
  [[ "$installed" == true ]] || exit 1
)

# The outer setup budget wins over a longer per-command allowance. Once expired,
# even the timeout fixture must not be invoked.
(
  source "$repo_dir/scripts/setup-h100.sh"
  setup_deadline=100; setup_system_path=/fixture/system; setup_temp=/fixture/private-temp
  setup_monotonic() { printf 95; }
  timeout() { printf '%s\n' "$@" > "$fixture_dir/bounded-args"; }
  setup_bounded 300 /fixture/tool literal-argument
  [[ $(sed -n '3p' "$fixture_dir/bounded-args") == 5 ]] || exit 1
  grep -Fxq PATH=/fixture/system "$fixture_dir/bounded-args"
  grep -Fxq TMPDIR=/fixture/private-temp "$fixture_dir/bounded-args"
  ! grep -q PRIVATE_CREDENTIAL_MARKER "$fixture_dir/bounded-args"
  setup_monotonic() { printf 100; }
  timeout() { echo 'Expired setup launched a command' >&2; exit 99; }
  if setup_bounded 300 /fixture/tool; then exit 1; else [[ "$?" == 124 ]] || exit 1; fi
)

printf 'PASS: hermetic H100 setup fixtures; no real Linux/CUDA/apt qualification. Artifacts: %s\n' "$fixture_dir"
