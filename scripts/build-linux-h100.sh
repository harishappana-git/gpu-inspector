#!/usr/bin/env bash
# Development build on a trusted Linux build host. Does not install packages,
# change the driver, qualify methods, or publish a release.
set -Eeuo pipefail
umask 077

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
stamp=$(date -u +%Y%m%dT%H%M%SZ)-$$
cuda_root=${CUDA_ROOT:-/usr/local/cuda}
build_dir="$repo_dir/build/linux-h100-$stamp"
output_dir="$repo_dir/dist/linux-h100-$stamp"
signing_key=
public_key=
usage() {
  cat <<'EOF'
Usage: bash scripts/build-linux-h100.sh [--cuda-root DIR] [--build-dir NEW_DIR]
       [--output NEW_DIR] [--signing-key PRIVATE_PEM --public-key PUBLIC_PEM]
Requires Linux x86-64, Go 1.24+, CMake 3.24+, C/C++ compilers and CUDA 12.0+.
Existing dependencies only. Builds SM90, runs software/CPU checks, stages a
signed unqualified development bundle. Without supplied keys, creates a new
development key in the private build directory; the private key is NOT staged.
EOF
}
while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --cuda-root|--build-dir|--output|--signing-key|--public-key)
      (($# >= 2)) || { usage >&2; exit 1; }
      case "$1" in
        --cuda-root) cuda_root=$2 ;;
        --build-dir) build_dir=$2 ;;
        --output) output_dir=$2 ;;
        --signing-key) signing_key=$2 ;;
        --public-key) public_key=$2 ;;
      esac
      shift 2 ;;
    *) usage >&2; exit 1 ;;
  esac
done
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Build requires native Linux x86-64.' >&2; exit 1; }
[[ -n "$signing_key" && -n "$public_key" || -z "$signing_key" && -z "$public_key" ]] || { echo 'Supply both signing keys.' >&2; exit 1; }
for tool in go cmake ctest cc c++ sha256sum readelf ldd; do
  command -v "$tool" >/dev/null || { echo "Missing build dependency: $tool" >&2; exit 1; }
done
[[ -x "$cuda_root/bin/nvcc" && -d "$cuda_root/lib64" ]] || { echo 'CUDA root must contain bin/nvcc and lib64.' >&2; exit 1; }
cuda_root=$(cd -- "$cuda_root" && pwd -P)
[[ ! -e "$build_dir" && ! -L "$build_dir" && ! -e "$output_dir" && ! -L "$output_dir" ]] || { echo 'Build and output directories must be new; prior attempts are retained.' >&2; exit 1; }
mkdir -p -- "$(dirname -- "$build_dir")" "$(dirname -- "$output_dir")"
mkdir -m 700 -- "$build_dir" "$output_dir"
build_dir=$(cd -- "$build_dir" && pwd -P)
output_dir=$(cd -- "$output_dir" && pwd -P)
mkdir -m 700 -- "$output_dir/bin" "$output_dir/libexec" "$output_dir/scripts" "$output_dir/docs"
exec > >(tee "$build_dir/build.log") 2>&1
echo 'Building a development H100 bundle; qualification remains pending.'
cd -- "$repo_dir"
export CGO_ENABLED=1
go version
cc --version
cmake --version
"$cuda_root/bin/nvcc" --version
go test ./...
go test -race ./...
go vet ./...
go build -trimpath -o "$output_dir/bin/gri" ./cmd/gri
cmake -S worker -B "$build_dir/worker" -DGRI_BUILD_CUDA=ON \
  -DCMAKE_BUILD_TYPE=Release -DCUDAToolkit_ROOT="$cuda_root" \
  -DCMAKE_CUDA_COMPILER="$cuda_root/bin/nvcc" \
  '-DGRI_CUDA_ARCHITECTURES=90-real;90-virtual' \
  -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON -DCMAKE_INSTALL_RPATH="$cuda_root/lib64"
cmake --build "$build_dir/worker" --parallel 2
ctest --test-dir "$build_dir/worker" --output-on-failure
cp -- "$build_dir/worker/gri-cuda-worker" "$output_dir/libexec/gri-cuda-worker"
chmod 700 -- "$output_dir/bin/gri" "$output_dir/libexec/gri-cuda-worker"
if [[ -z "$signing_key" ]]; then
  "$output_dir/bin/gri" keys generate --output "$build_dir/development-keys"
  signing_key="$build_dir/development-keys/private.pem"
  public_key="$build_dir/development-keys/public.pem"
fi
"$output_dir/bin/gri" manifest worker --platform linux-amd64 \
  --binary "$output_dir/libexec/gri-cuda-worker" --output "$output_dir/worker-manifest.json"
"$output_dir/bin/gri" sign --input "$output_dir/worker-manifest.json" \
  --key "$signing_key" --verify-public-key "$public_key" --output "$output_dir/worker-envelope.json"
cp -- "$public_key" "$output_dir/worker-public.pem"
cp -- scripts/run-h100.sh "$output_dir/scripts/run-h100.sh"
cp -- docs/H100_SINGLE_NODE.md docs/ACCEPTANCE.md docs/IMPLEMENTATION_STATUS.md "$output_dir/docs/"
ldd_output=$(ldd "$output_dir/libexec/gri-cuda-worker")
if [[ "$ldd_output" == *'not found'* ]]; then
  printf '%s\n' "$ldd_output" > "$output_dir/unresolved-dependencies.txt"
  echo 'Unresolved runtime dependency; retaining incomplete build for investigation.' >&2
  exit 1
fi
{
  echo 'DEVELOPMENT / UNQUALIFIED. Shared libraries are resolved from the qualified host environment; they are not bundled.'
  go version
  "$cuda_root/bin/nvcc" --version
  git rev-parse HEAD 2>/dev/null || true
  git diff --stat 2>/dev/null || true
  readelf -d "$output_dir/libexec/gri-cuda-worker"
  printf '%s\n' "$ldd_output"
} > "$output_dir/build-provenance.txt"
cd -- "$output_dir"
sha256sum bin/gri libexec/gri-cuda-worker worker-public.pem worker-manifest.json \
  worker-envelope.json scripts/run-h100.sh docs/*.md build-provenance.txt > SHA256SUMS
sha256sum --check SHA256SUMS
echo "Bundle: $output_dir"
echo "Private build logs/keys remain in: $build_dir"
echo 'Verify the public-key fingerprint independently, then use scripts/run-h100.sh on the authorized H100.'
