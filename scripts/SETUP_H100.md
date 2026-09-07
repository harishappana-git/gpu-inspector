# Noninteractive H100 setup

`setup-h100.sh` prepares tools for the development H100 campaign on native
Ubuntu 22.04 or 24.04, x86-64. A working NVIDIA driver must already exist.
The remote controller invokes it after SSH configuration; it can also run as:

```bash
bash scripts/setup-h100.sh --prefix /tmp/gri-run/toolchain \
  --output-env /tmp/gri-run/setup.env --install-system-deps \
  --budget-seconds 1800
source /tmp/gri-run/setup.env
```

The prefix and output parent must be owned private directories. Each invocation
requires a new environment/status filename and retains a unique setup attempt.
Reusing a prefix reuses validated tools and checksum-verified cached downloads.
An invalid cached archive or incomplete final installation is preserved and
rejected; it is never executed or silently replaced.

Existing Go 1.24+ and CMake 3.24+ are preferred from fixed system locations.
Otherwise the script installs private Go 1.24.5 and CMake 3.31.6. Ubuntu 22.04's
older packaged CMake cannot satisfy this build and is therefore not reused.
`--cuda-root` selects an explicit existing CUDA 12.8.1 installation; an incomplete
or mismatched explicit selection fails without substituting another toolkit.
Without that option, a complete validated existing toolkit is reused or NVIDIA
12.8.1 component archives are assembled under the private prefix. The selected
components are nvcc/NVVM, CUDA runtime, CCCL, cuBLAS/cuBLASLt and Compute Sanitizer.
No NVIDIA driver installer, compatibility driver, repository or service is added.

All downloaded archives have fixed HTTPS origins and SHA-256 hashes pinned in
the script. The CUDA hashes and sizes come from NVIDIA's versioned release
manifest. About 1.03 GB of CUDA archives are downloaded when nothing can be
reused; at least 8 GiB free is required for retained archives, extraction and
assembly. Network, extraction, compiler and package commands have bounded
timeouts within the setup budget, measured using Linux monotonic uptime. GNU
timeout allows at most five additional seconds to kill a nonresponsive child.

Missing system compiler/build/download dependencies are an explicit failure
unless `--install-system-deps` was supplied. With that flag, root or `sudo -n`
must work; passwords are never requested. The script uses the machine's existing
signed apt repositories to install build-essential, binutils, git, curl,
ca-certificates and xz-utils, with lock and execution timeouts. It requests no
package removals, blanket upgrade, driver change, reboot or security-policy
change. Package-manager failures remain failures; setup does not attempt to
repair host package state automatically.

Validation checks exact CUDA/nvcc and cuBLAS header versions, required runtime
files, Compute Sanitizer version and a small SM90 compile/link against cudart,
cuBLAS and cuBLASLt. **The compiled program is never executed during setup.**
This does not validate GPU access, kernel execution, sanitizer injection,
runtime compatibility, memory correctness, performance or H100 qualification.
The subsequent selected-device campaign records those outcomes separately.

DCGM is optional. Setup records whether an already installed 4.6.0 client and
existing loopback hostengine are available. It does not install or start DCGM.
A missing/unavailable DCGM installation does not block the remaining campaign;
its attempted diagnostic is recorded with an explicit dependency/service gap.

Only a successful setup publishes the sourceable environment, with allowlisted
PATH, CUDA_ROOT, CUDAToolkit_ROOT, CUDACXX, GOTOOLCHAIN and private TMPDIR exports.
`setup.env.json` records status, selected paths and normalized tool versions.
The manifest's `setup_log` names the private normalized phase log. Neither file
contains inherited environment values, credentials, raw driver/process listings,
apt output or arbitrary command error text. Download the JSON and named log with
campaign artifacts; exclude the toolchain/download cache and build directories.
`--dry-run` records a plan without compiler/driver commands, network or apt and
does not publish a usable environment.

Run `bash scripts/test-h100-setup.sh` for hermetic fixtures on Linux or Git Bash.
These fixtures replace platform/tool effects; they test no real driver,
download/install, apt transaction or native Linux compilation. Native H100
end-to-end execution remains a release gate.

Primary pin sources:

- [Go release SHA-256 inventory](https://go.dev/dl/#go1.24.5)
- [Kitware CMake 3.31.6 SHA-256 inventory](https://github.com/Kitware/CMake/releases/download/v3.31.6/cmake-3.31.6-SHA-256.txt)
- [NVIDIA CUDA 12.8.1 component hashes](https://developer.download.nvidia.com/compute/cuda/redist/redistrib_12.8.1.json)
- [NVIDIA CUDA 12.8.1 Linux platform/compiler and archive documentation](https://docs.nvidia.com/cuda/archive/12.8.1/cuda-installation-guide-linux/index.html)
