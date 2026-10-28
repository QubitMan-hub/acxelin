# Install Acxelin for this user on Windows:  Unblock-File .\install.ps1; powershell -ExecutionPolicy RemoteSigned -File .\install.ps1      (remove: ... -Uninstall)
# Works offline from a release wheelhouse (the .whl files next to this script) or from a checkout of the repository.
param([switch]$Uninstall)
$ErrorActionPreference = "Stop"
$Product = "vpn"
$cmd = "acxelin-$Product"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = if ($env:ACXELIN_PREFIX) { $env:ACXELIN_PREFIX } else { Join-Path $env:LOCALAPPDATA "Acxelin" }
$home_ = Join-Path $root $Product
$bin = if ($env:ACXELIN_BIN) { $env:ACXELIN_BIN } else { Join-Path $root "bin" }

if ($Uninstall) {
  Remove-Item -Recurse -Force $home_, (Join-Path $bin "$cmd.cmd") -ErrorAction SilentlyContinue
  Write-Output "Removed $cmd. Your certificates, consoles and settings stay where you put them."
  exit 0
}

$py = $null
foreach ($c in @("py", "python")) {
  if (Get-Command $c -ErrorAction SilentlyContinue) {
    $args3 = @(if ($c -eq "py") { "-3" })  # always a list: a splatted string goes in one character at a time
    & $c @args3 -c "import sys; sys.exit(sys.version_info < (3, 11))" 2>$null
    if ($LASTEXITCODE -eq 0) { $py = @($c) + $args3; break }
  }
}
if (-not $py) { Write-Error "$cmd needs Python 3.11 or newer. Install it from python.org (tick 'Add to PATH'), then run this again."; exit 1 }

Write-Output "Installing $cmd into $home_"
if (Test-Path $home_) { Remove-Item -Recurse -Force $home_ }
New-Item -ItemType Directory -Force -Path $bin | Out-Null
& $py[0] @($py | Select-Object -Skip 1) -m venv $home_
$python = Join-Path $home_ "Scripts\python.exe"
if (Get-ChildItem -Path $here -Filter *.whl -ErrorAction SilentlyContinue) {
  Write-Output "  from the wheels next to it (offline)"
  $extra = if (Test-Path (Join-Path $here "extras")) { (Get-Content (Join-Path $here "extras") -Raw).Trim() } else { "" }
  $ErrorActionPreference = "Continue"  # pip's message on stderr must not stop the script before the fallback runs
  & $python -m pip install -q --no-index --find-links $here "$cmd$extra" 2>$null
  if ($LASTEXITCODE -ne 0) { & $python -m pip install -q --no-index --find-links $here $cmd }  # without them where they have no wheel
  $ErrorActionPreference = "Stop"
} elseif ((Test-Path (Join-Path $here "pyproject.toml")) -and (Test-Path (Join-Path $here "..\..\core"))) {
  Write-Output "  from this checkout"
  & $python -m pip install -q (Join-Path $here "..\..\core") $here
} else {
  Write-Error "Run this script from a release wheelhouse folder or from products\$Product in a checkout."; exit 1
}
if ($LASTEXITCODE -ne 0) { Write-Error "pip could not install $cmd"; exit 1 }

# OpenSSL 3.5+ for post-quantum TLS: the folder you point at, or the usual installer's folder (choco install openssl).
$ssl = $env:ACXELIN_OPENSSL
if (-not $ssl -and (Test-Path "C:\Program Files\OpenSSL-Win64\bin")) { $ssl = "C:\Program Files\OpenSSL-Win64\bin" }
if (-not $ssl) { $note = "If doctor reports no OpenSSL 3.5+ below: choco install openssl (or install OpenSSL 3.5+ elsewhere and set ACXELIN_OPENSSL to its bin folder), then run this installer again." }
$wrapper = @("@echo off")
if ($ssl) { $wrapper += "if not defined ACXELIN_OPENSSL set `"ACXELIN_OPENSSL=$ssl`"" }
$wrapper += "`"$(Join-Path $home_ "Scripts\$cmd.exe")`" %*"
Set-Content -Path (Join-Path $bin "$cmd.cmd") -Value $wrapper -Encoding Oem  # cmd.exe reads the console code page; ASCII would turn a name such as José into Jos?

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not (($userPath -split ";") -contains $bin)) {
  [Environment]::SetEnvironmentVariable("Path", "$userPath;$bin", "User")
  Write-Output "Added $bin to your PATH; open a new terminal to use $cmd from anywhere."
}
$env:Path = "$env:Path;$bin"
Write-Output ""
if ($note) { Write-Output $note; Write-Output "" }
& (Join-Path $bin "$cmd.cmd") doctor
Write-Output ""
& (Join-Path $bin "$cmd.cmd") | Select-String -Pattern "Start here" -Context 0,10 | ForEach-Object { $_.Line; $_.Context.PostContext }
