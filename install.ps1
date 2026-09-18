# Install the tunneler CLI on Windows:
#
#   irm https://raw.githubusercontent.com/mtsaas/tunneler/main/install.ps1 | iex
#
# Uses the Go toolchain if there is one, otherwise builds in Docker.
#   $env:TUNNELER_VERSION      version to install (default: latest)
#   $env:TUNNELER_INSTALL_DIR  where the Docker build puts the binary
#                              (default: %LOCALAPPDATA%\tunneler\bin)
$ErrorActionPreference = 'Stop'

$version = if ($env:TUNNELER_VERSION) { $env:TUNNELER_VERSION } else { 'latest' }
$pkg = "github.com/mtsaas/tunneler/cmd/tunneler@$version"

if (Get-Command go -ErrorAction SilentlyContinue) {
    Write-Host 'Installing with go...'
    go install $pkg
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $dir = go env GOBIN
    if (-not $dir) { $dir = Join-Path (go env GOPATH) 'bin' }
}
elseif (Get-Command docker -ErrorAction SilentlyContinue) {
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
    $dir = if ($env:TUNNELER_INSTALL_DIR) { $env:TUNNELER_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'tunneler\bin' }
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Write-Host "Building for windows/$arch in Docker..."
    # A cross-compiled "go install" lands in bin/windows_<arch>/.
    docker run --rm -e GOOS=windows -e GOARCH=$arch -e CGO_ENABLED=0 -v "${dir}:/out" golang:1.26 `
        sh -c "go install $pkg && cp `$(find /go/bin -type f -name tunneler.exe) /out/tunneler.exe"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
else {
    Write-Error 'Install Go (https://go.dev/dl) or Docker (https://docs.docker.com/get-docker), then run this again.'
    exit 1
}

$exe = Join-Path $dir 'tunneler.exe'
$installed = (& $exe version 2>$null | Select-Object -First 1) -replace '^client:\s*', ''
Write-Host "Installed: $exe ($installed)"
if (($env:PATH -split ';') -notcontains $dir) {
    Write-Host "Add it to your PATH:  [Environment]::SetEnvironmentVariable('PATH', `"$dir;`$env:PATH`", 'User')"
}
Write-Host 'Next:  tunneler config --server <coordinator URL>'
