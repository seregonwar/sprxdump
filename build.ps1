# Build sprxdump.elf with the ps5-payload-sdk clang driver (Windows path).
#
#   pwsh -File build.ps1
#   pwsh -File build.ps1 -Out .\out
#
# Sources: src\*.c -> build\sprxdump.elf (one ELF, no shared objects).
param(
  [string]$Sdk = "D:\source\repos\Github\_sdk-044\ps5-payload-sdk",
  [string]$Out = ""
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path "$Sdk\target\lib\crt1.o")) {
  throw "ps5-payload-sdk not found at $Sdk (need target\lib\crt1.o)"
}
if (-not $Out) { $Out = Join-Path $PSScriptRoot "build" }

$clang = "C:\Program Files\LLVM\bin\clang.exe"
if (-not (Test-Path $clang)) { $clang = (Get-Command clang).Source }

# clang resolves the PS5 linker (prospero-lld.exe) through the SDK's win\ dir.
$env:PATH = "$env:PATH;$Sdk\win"

$common = @(
  "-target","x86_64-sie-ps5",
  "--sysroot=$Sdk",
  "-isystem","$Sdk\target\include",
  "-L","$Sdk\target\lib",
  "-fno-stack-protector","-fno-plt","-femulated-tls",
  "-O2","-Wall","-Wextra","-g"
)
$libs = @("-lc","-lkernel_web","-lSceLibcInternal","-lSceNet")

New-Item -ItemType Directory -Force $Out | Out-Null

$src = Join-Path $PSScriptRoot "src\sprxdump.c"
$out = Join-Path $Out "sprxdump.elf"
Write-Host ("building sprxdump <- {0}" -f $src.Replace($PSScriptRoot + '\', ''))
& $clang @common -I(Join-Path $PSScriptRoot "src") -o $out $src @libs
if ($LASTEXITCODE -ne 0) { throw "build failed (exit $LASTEXITCODE)" }
Write-Host ("  -> {0} ({1} bytes)" -f $out, (Get-Item $out).Length)
