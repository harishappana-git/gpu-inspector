param(
    [string]$Config,
    [string]$Resume,
    [string]$Output,
    [switch]$PrepareOnly
)
# Native Windows entry point; portable Python bootstrap does not change PATH or
# install an OS service. The Python controller owns all SSH and GPU coordination.
$ErrorActionPreference='Stop'
if (([bool]$Config) -eq ([bool]$Resume)) { throw 'Supply exactly one of -Config or -Resume.' }
$repoRoot=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$pythonRoot=Join-Path $repoRoot 'build/.toolchains/python-3.13.12'
$pythonExe=Join-Path $pythonRoot 'python.exe'
if (-not (Test-Path -LiteralPath $pythonExe -PathType Leaf)) {
    $toolchainParent=Split-Path $pythonRoot
    New-Item -ItemType Directory -Force -Path $toolchainParent | Out-Null
    $archive=Join-Path $toolchainParent ('python-bootstrap-'+[Guid]::NewGuid().ToString('N')+'.zip')
    $expected='76f238f606250c87c6beac75dccd35ee99070a13490555936abb6cb64ecce3d0'
    [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
    Write-Output 'Downloading pinned portable Python 3.13.12 from python.org'
    Invoke-WebRequest -UseBasicParsing -Uri 'https://www.python.org/ftp/python/3.13.12/python-3.13.12-embed-amd64.zip' -OutFile $archive -TimeoutSec 180
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'Python SHA256 mismatch; archive was not executed.' }
    if (Test-Path -LiteralPath $pythonRoot) { throw 'An incomplete Python directory exists; it has been preserved.' }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($archive,$pythonRoot)
}
$controllerArgs=@((Join-Path $PSScriptRoot 'h100-remote.py'))
if ($Config) { $controllerArgs+=@('--config',$Config) } else { $controllerArgs+=@('--resume',$Resume) }
if ($Output) { $controllerArgs+=@('--output',$Output) }
if ($PrepareOnly) { $controllerArgs+='--prepare-only' }
& $pythonExe @controllerArgs
exit $LASTEXITCODE
