param(
    [string]$CudaRoot = $env:CUDA_PATH,
    [string]$Architectures = '120-real;120-virtual',
    [string]$BuildDir = 'build/worker-windows',
    [switch]$CPUOnly
)

# Run in a Visual Studio x64 developer PowerShell with Go and CMake on PATH.
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
Push-Location $projectRoot
try {
    foreach ($command in @('go', 'cmake', 'ctest', 'cl')) {
        if (!(Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "Missing $command. Use a Visual Studio x64 developer PowerShell with Go and CMake on PATH."
        }
    }
    New-Item -ItemType Directory -Force bin | Out-Null
    & go build -trimpath -o bin/gri.exe ./cmd/gri
    if ($LASTEXITCODE) { throw 'CLI build failed' }
    $generator = 'NMake Makefiles'
    if (Get-Command ninja -ErrorAction SilentlyContinue) { $generator = 'Ninja' }
    $configure = @('-S', 'worker', '-B', $BuildDir, '-G', $generator, '-DCMAKE_BUILD_TYPE=Release')
    if ($CPUOnly) {
        $configure += '-DGRI_BUILD_CUDA=OFF'
    } else {
        if (!$CudaRoot -or !(Test-Path -LiteralPath (Join-Path $CudaRoot 'bin/nvcc.exe'))) {
            throw 'CUDA Toolkit 12.8+ is required for RTX 5080. Set -CudaRoot to its installation directory.'
        }
        $configure += @('-DGRI_BUILD_CUDA=ON', "-DCUDAToolkit_ROOT=$CudaRoot", "-DCMAKE_CUDA_COMPILER=$CudaRoot/bin/nvcc.exe", "-DGRI_CUDA_ARCHITECTURES=$Architectures")
    }
    & cmake @configure
    if ($LASTEXITCODE) { throw 'Worker configuration failed' }
    if ($generator -eq 'Ninja') {
        & cmake --build $BuildDir --parallel 2
    } else {
        & cmake --build $BuildDir
    }
    if ($LASTEXITCODE) { throw 'Worker build failed' }
    & ctest --test-dir $BuildDir --output-on-failure
    if ($LASTEXITCODE) { throw 'CPU validation failed' }
    if (!$CPUOnly) {
        foreach ($name in @('cudart64_12.dll', 'cublas64_12.dll', 'cublasLt64_12.dll')) {
            $source = Join-Path $CudaRoot "bin/$name"
            if (!(Test-Path -LiteralPath $source)) { throw "Missing runtime DLL: $source" }
            Copy-Item -LiteralPath $source -Destination (Join-Path $BuildDir $name)
        }
    }
    Write-Output "Development build complete: bin/gri.exe and $BuildDir. Sign the worker and each staged DLL before scanning. Qualification remains pending."
} finally {
    Pop-Location
}
