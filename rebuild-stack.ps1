param(
  [string]$PythonExe = "python",
  [string]$Workspace = "C:\Users\User\Code",
  [string]$MitmproxyPath = "C:\Users\User\Code\mitmproxy",
  [string]$MitmproxyRsPath = "C:\Users\User\Code\mitmproxy_rs",
  [string]$VenvPath = "C:\Users\User\Code\mitmproxy_rs\.venv"
)

$ErrorActionPreference = "Stop"

function Run-Step {
  param([string]$Message, [scriptblock]$Cmd)
  Write-Host "==> $Message"
  & $Cmd
}

Run-Step "Creating virtualenv (Python 3.12 required)" {
  if (-not (Test-Path $VenvPath)) {
    & $PythonExe -m venv $VenvPath
  }
}

$PythonExe = Join-Path $VenvPath "Scripts\python.exe"

Run-Step "Upgrading pip" { & $PythonExe -m pip install --upgrade pip }

Run-Step "Removing old mitmproxy-rs/mitmproxy-windows installs" {
  & $PythonExe -m pip uninstall -y mitmproxy-rs mitmproxy_rs mitmproxy-windows
}

Run-Step "Installing mitmproxy (editable)" {
  & $PythonExe -m pip install -e $MitmproxyPath
}

Run-Step "Building mitmproxy_rs (Rust extension)" {
  & $PythonExe -m pip install maturin
  Push-Location "$MitmproxyRsPath\mitmproxy-rs"
  try {
    & $PythonExe -m maturin develop
  } finally {
    Pop-Location
  }
}

Run-Step "Building Windows redirector (release)" {
  Push-Location $MitmproxyRsPath
  try {
    & cargo build -p windows-redirector --release
  } finally {
    Pop-Location
  }
}

Run-Step "Installing mitmproxy-windows package" {
  & $PythonExe -m pip install "$MitmproxyRsPath\mitmproxy-windows"
}

Write-Host "Done."
