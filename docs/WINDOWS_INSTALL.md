# CABTA — Windows Installation Guide

## Requirements

### Python packages

Install the project dependencies from the repository root. `requirements.txt` selects `python-magic-bin` on Windows:

```powershell
python -m pip install -r requirements.txt
```

---

## External tool installation

### 1. Mandiant capa (capability detection)

**Download:**

- https://github.com/mandiant/capa/releases
- Download the `capa-vX.X.X-windows.zip` release archive.

**Install:**

```powershell
# Extract the archive and add its directory to PATH
Expand-Archive capa-v7.0.1-windows.zip -DestinationPath C:\Tools\capa
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Tools\capa", "User")

# Verify
capa --version
```

---

### 2. Mandiant FLOSS (obfuscated string extraction)

**Download:**

- https://github.com/mandiant/flare-floss/releases
- Download the `floss-vX.X.X-windows.zip` release archive.

**Install:**

```powershell
Expand-Archive floss-v3.1.0-windows.zip -DestinationPath C:\Tools\floss
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Tools\floss", "User")

# Verify
floss --version
```

---

### 3. Detect It Easy (DIE) — packer/compiler detection

**Download:**

- https://github.com/horsicq/DIE-engine/releases
- Download the `die_win64_portable_X.XX.zip` release archive.

**Install:**

```powershell
Expand-Archive die_win64_portable_3.09.zip -DestinationPath C:\Tools\die
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Tools\die", "User")

# Verify the CLI version
diec --version
```

---

### 4. binwalk (firmware/embedded analysis)

**Option A — WSL (recommended):**

```powershell
# Run this when WSL is installed
wsl sudo apt install binwalk
```

**Option B — native Windows:**

```powershell
pip install binwalk
```

> **Note:** Native Windows binwalk may not support every extraction feature. WSL is recommended for critical firmware analysis.

---

### 5. Didier Stevens PDF Tools

**Download:**

- https://github.com/DidierStevens/DidierStevensSuite

**Install:**

```powershell
# Clone the repository, or download and extract its ZIP archive
git clone https://github.com/DidierStevens/DidierStevensSuite.git C:\Tools\DidierStevens

# Add the directory to PATH
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Tools\DidierStevens", "User")

# Verify direct script execution
python C:\Tools\DidierStevens\pdfid.py sample.pdf
python C:\Tools\DidierStevens\pdf-parser.py sample.pdf
```

---

## Recommended directory structure

```text
C:\Tools\
├── capa\
│   └── capa.exe
├── floss\
│   └── floss.exe
├── die\
│   ├── diec.exe
│   └── die.exe (GUI)
└── DidierStevens\
    ├── pdfid.py
    └── pdf-parser.py
```

---

## Configure PATH in one step

```powershell
# Add every native tool/script directory to the user PATH
$newPaths = @(
    "C:\Tools\capa",
    "C:\Tools\floss",
    "C:\Tools\die",
    "C:\Tools\DidierStevens"
)

$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
$newPath = $currentPath + ";" + ($newPaths -join ";")
[Environment]::SetEnvironmentVariable("Path", $newPath, "User")

# Open a new terminal before running the verification commands
```

---

## Verify the installation

```powershell
Write-Host "=== CABTA Tool Check ===" -ForegroundColor Cyan

$tools = @{
    "capa" = "capa --version"
    "floss" = "floss --version"
    "diec" = "diec --version"
    "binwalk" = "binwalk --version"
    "pdfid" = "python -c `"import sys; sys.path.insert(0,'C:\\Tools\\DidierStevens'); import pdfid; print('OK')`""
    "pdf-parser" = "if (Test-Path -LiteralPath 'C:\Tools\DidierStevens\pdf-parser.py') { 'OK' } else { throw 'pdf-parser.py not found' }"
}

foreach ($tool in $tools.Keys) {
    try {
        $result = Invoke-Expression $tools[$tool] 2>&1
        Write-Host "[OK] $tool" -ForegroundColor Green
    } catch {
        Write-Host "[MISSING] $tool" -ForegroundColor Red
    }
}
```

---

## How CABTA Finds These Tools

CABTA has two separate tool-resolution mechanisms. They serve different execution paths and are not interchangeable.

### Main analysis pipeline

`src/tools/external_tool_runner.py::_discover_tools()` is used by `pe_analyzer.py`, `pdf_analyzer.py`, `firmware_analyzer.py`, and `obfuscated_string_analyzer.py`.

At startup, it calls `shutil.which()` once for each candidate in `TOOL_BINARIES`. There is no fallback directory. If a tool cannot be found on `PATH` during startup, it remains unavailable to the main analysis pipeline for that session. After changing `PATH`, open a new terminal and restart CABTA.

### MCP FLARE tool layer

`src/mcp_servers/flare_tools.py` is used only by the MCP tools `capa_analyze`, `floss_extract`, and `diec_identify`. This layer uses `shutil.which()` and then hardcoded fallbacks such as `C:\Tools\capa\capa.exe`.

Those fallback paths help only the MCP FLARE layer. They do not make the tools discoverable by the main analysis pipeline.

**Always add each installed tool directory to the system or user `PATH`. Do not rely solely on the `C:\Tools\...` MCP fallback paths.**

---

## Known Windows issues

| Tool | Issue | Suggested action |
|---|---|---|
| binwalk | Some extraction features may not work natively | Use WSL |
| FLOSS | Analysis may take 5–10 minutes | Increase the relevant timeout |
| capa | Large files may take longer to analyze | Use JSON output where appropriate |

---

## Quick Start with Chocolatey

```powershell
# Install Python when Chocolatey is available
choco install python -y

# Install project Python packages from the repository root
python -m pip install -r requirements.txt

# Download capa, FLOSS, and Detect It Easy manually from their release pages
# Install Didier Stevens PDF Tools from its GitHub repository
# Install binwalk through WSL or pip as described above
```

---

## Direct download links

| Tool | Link |
|---|---|
| capa | https://github.com/mandiant/capa/releases/latest |
| FLOSS | https://github.com/mandiant/flare-floss/releases/latest |
| Detect It Easy | https://github.com/horsicq/DIE-engine/releases/latest |
| PDF Tools | https://github.com/DidierStevens/DidierStevensSuite |
