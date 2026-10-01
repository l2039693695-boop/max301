# Downloads the Wintun driver and places wintun.dll beside the client.
#
# The client needs this DLL at runtime; Wintun is the same driver WireGuard uses
# on Windows. Run from the directory holding max301-client.exe.
#
# Usage: .\install-wintun.ps1 [-Version 0.14.1]

param(
    [string]$Version = "0.14.1",
    [string]$Destination = "."
)

$ErrorActionPreference = "Stop"

# Wintun ships one DLL per architecture; pick the one matching this machine.
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    "x86"   { "x86" }
    default { throw "unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
}

$url = "https://www.wintun.net/builds/wintun-$Version.zip"
$zip = Join-Path $env:TEMP "wintun-$Version.zip"
$unpacked = Join-Path $env:TEMP "wintun-$Version"

Write-Host "Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing

if (Test-Path $unpacked) { Remove-Item -Recurse -Force $unpacked }
Expand-Archive -Path $zip -DestinationPath $unpacked -Force

$dll = Join-Path $unpacked "wintun\bin\$arch\wintun.dll"
if (-not (Test-Path $dll)) {
    throw "wintun.dll for $arch not found in the archive"
}

$target = Join-Path (Resolve-Path $Destination) "wintun.dll"
Copy-Item -Path $dll -Destination $target -Force

Remove-Item $zip -Force
Remove-Item -Recurse -Force $unpacked

Write-Host "Installed $target ($arch)"
Write-Host ""
Write-Host "The client must run as administrator: it creates a network adapter"
Write-Host "and edits the route table."
