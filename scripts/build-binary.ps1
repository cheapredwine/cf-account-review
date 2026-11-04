#!/usr/bin/env pwsh
# Build the standalone cf-account-review binary on Windows (Node single-executable).
# Mirrors scripts/build-binary.sh: official nodejs.org build (SEA support), esbuild
# CJS bundle, postject embed with the sentinel read from the binary.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$NodeVersion = if ($args.Count -gt 0) { $args[0] } else { "24.22.2" }
$os = "win"
$arch = "x64"
$zip = ".cache/node-v$NodeVersion-$os-$arch.zip"
$url = "https://nodejs.org/dist/v$NodeVersion/node-v$NodeVersion-$os-$arch.zip"

if (-not (Test-Path ".cache/node-v$NodeVersion-$os-$arch/node.exe")) {
    Write-Host "downloading official node v$NodeVersion ($os-$arch) for the SEA embed..."
    New-Item -ItemType Directory -Force -Path .cache | Out-Null
    Invoke-WebRequest -Uri $url -OutFile $zip
    Expand-Archive -Path $zip -DestinationPath .cache -Force
    Remove-Item $zip
}
$seaNode = (Resolve-Path ".cache/node-v$NodeVersion-$os-$arch/node.exe").Path

Write-Host "bundling CLI with esbuild..."
pnpm build
./node_modules/.bin/esbuild dist/cli.js --bundle --platform=node --format=cjs --outfile=dist/cli.bundle.cjs
if ($LASTEXITCODE -ne 0) { exit 1 }

@"
{
	`"main`": `"dist/cli.bundle.cjs`",
	`"output`": `"dist/sea.blob`",
	`"disableExperimentalSEAWarning`": true
}
"@ | Set-Content -NoNewline sea-config.json

Write-Host "generating SEA blob..."
& $seaNode --experimental-sea-config sea-config.json
if ($LASTEXITCODE -ne 0) { exit 1 }

$out = "dist/cf-account-review-$os-$arch.exe"
Copy-Item $seaNode $out -Force

Write-Host "extracting SEA fuse sentinel from the node binary..."
$bytes = [System.IO.File]::ReadAllBytes($seaNode)
$text = [System.Text.Encoding]::ASCII.GetString($bytes)
$m = [regex]::Match($text, "NODE_SEA_FUSE_[a-f0-9]{32}")
if (-not $m.Success) { Write-Error "no SEA fuse sentinel found in the node binary"; exit 1 }
$sentinel = $m.Value

Write-Host "embedding into node binary -> $out"
./node_modules/.bin/postject $out NODE_SEA_BLOB dist/sea.blob --sentinel-fuse $sentinel
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "smoke:"
& $out --help *> $null
if ($LASTEXITCODE -ne 0) { Write-Error "binary --help failed"; exit 1 }
Write-Host "  --help ok"
Write-Host "binary ready: $out"
