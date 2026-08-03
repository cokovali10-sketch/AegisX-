# PowerShell codegen for the AegisX proto contract.
# Requires: protoc, protoc-gen-go, protoc-gen-go-grpc, grpcio-tools, protoc-gen-kotlin.
param(
  [switch]$SkipKotlin
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$protoDir = Join-Path $root "proto"
$genDir = Join-Path $protoDir "gen"
$goPb = Join-Path $genDir "go"
$pyPb = Join-Path $genDir "python"

New-Item -ItemType Directory -Force -Path $goPb | Out-Null
New-Item -ItemType Directory -Force -Path $pyPb | Out-Null

# Go
& protoc --proto_path=$protoDir `
  --go_out=$goPb --go_opt=paths=source_relative `
  --go-grpc_out=$goPb --go-grpc_opt=paths=source_relative `
  (Join-Path $protoDir "aegisx.proto")
if ($LASTEXITCODE -ne 0) { throw "Go codegen failed" }

# Python
& python -m grpc_tools.protoc --proto_path=$protoDir `
  --python_out=$pyPb --grpc_python_out=$pyPb `
  (Join-Path $protoDir "aegisx.proto")
if ($LASTEXITCODE -ne 0) { throw "Python codegen failed" }

if (-not $SkipKotlin) {
  New-Item -ItemType Directory -Force -Path (Join-Path $genDir "kotlin") | Out-Null
  & protoc --proto_path=$protoDir --kotlin_out=(Join-Path $genDir "kotlin") `
    (Join-Path $protoDir "aegisx.proto")
  if ($LASTEXITCODE -ne 0) { throw "Kotlin codegen failed" }
}

Write-Host "[ok] AegisX proto artifacts generated under $genDir"
