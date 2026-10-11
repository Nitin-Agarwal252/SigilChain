param(
    [string]$InputFile,
    [string[]]$Recipients = @("nitin", "ashish"),
    [string]$DecryptAs,
    [string]$DocumentId = "demo-$(Get-Date -Format yyyyMMdd-HHmmss)",
    [string]$BundleDirectory = $(if (Test-Path (Join-Path $PSScriptRoot "sigilchain-images.tar")) { $PSScriptRoot } else { Join-Path $PSScriptRoot "dist\airgap" })
)

$ErrorActionPreference = "Stop"
$project = (Resolve-Path $PSScriptRoot).Path
$bundle = (Resolve-Path $BundleDirectory).Path
$composeFile = Join-Path $bundle "docker-compose.yml"
if (-not (Test-Path -LiteralPath $composeFile)) {
    throw "No offline Compose bundle found at '$bundle'. Run scripts\export_airgap_bundle.ps1 first."
}
if (-not $Recipients -or $Recipients.Count -eq 0) {
    throw "Provide at least one recipient ID with -Recipients."
}
foreach ($recipient in $Recipients) {
    if ($recipient -notmatch '^[A-Za-z0-9_.-]{1,64}$') {
        throw "Invalid recipient ID '$recipient'. Use only letters, numbers, dot, underscore, or hyphen."
    }
}
if (-not $DecryptAs) { $DecryptAs = $Recipients[0] }
if ($Recipients -notcontains $DecryptAs) {
    throw "DecryptAs '$DecryptAs' must be in Recipients: $($Recipients -join ', ')."
}
if ($DocumentId -notmatch '^[A-Za-z0-9._-]{1,80}$') {
    throw "DocumentId may contain only letters, numbers, dot, underscore, and hyphen (max 80 chars)."
}

$dataRoot = Join-Path $bundle "cli-data"
$inputDirectory = Join-Path $dataRoot "demo-input"
$outputDirectory = Join-Path $dataRoot "decrypted"
New-Item -ItemType Directory -Force -Path $inputDirectory, $outputDirectory | Out-Null

function Invoke-Compose {
    param([Parameter(Mandatory)][string[]]$ComposeArgs)
    $priorErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
        $priorNativeErrorAction = $PSNativeCommandUseErrorActionPreference
        $PSNativeCommandUseErrorActionPreference = $false
    }
    try {
        & docker compose --project-directory $bundle -f $composeFile @ComposeArgs
        $composeExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $priorErrorAction
        if (Test-Path variable:priorNativeErrorAction) { $PSNativeCommandUseErrorActionPreference = $priorNativeErrorAction }
    }
    if ($composeExitCode -ne 0) { throw "Docker Compose failed (exit $composeExitCode): $($ComposeArgs -join ' ')" }
}

function Invoke-QuietCompose {
    param([Parameter(Mandatory)][string[]]$ComposeArgs)
    $priorErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
        $priorNativeErrorAction = $PSNativeCommandUseErrorActionPreference
        $PSNativeCommandUseErrorActionPreference = $false
    }
    try {
        & docker compose --project-directory $bundle -f $composeFile @ComposeArgs *> $null
        return $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $priorErrorAction
        if (Test-Path variable:priorNativeErrorAction) { $PSNativeCommandUseErrorActionPreference = $priorNativeErrorAction }
    }
}

function Invoke-Cli {
    param([Parameter(Mandatory)][string[]]$CliArgs)
    Invoke-Compose -ComposeArgs (@("--profile", "tools", "run", "--rm", "cli") + $CliArgs)
}

function Show-Stage([int]$Number, [string]$Title) {
    Write-Host "`nSTAGE $Number OF 5 - $Title" -ForegroundColor Cyan
}

function Wait-ForEnter([string]$Message) {
    [void](Read-Host $Message)
}

try {
    Show-Stage 1 "SETUP AND VALIDATOR TRUST"
    $portOwners = @(& docker ps --filter "publish=8501" --format "{{.Names}}")
    if ($LASTEXITCODE -ne 0) { throw "Docker is unavailable. Start Docker Desktop, then rerun this script." }
    $expectedPrefix = "$(Split-Path -Leaf $bundle)-"
    $conflictingOwners = @($portOwners | Where-Object { $_ -and -not $_.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase) })
    if ($conflictingOwners.Count -gt 0) {
        throw "Port 8501 is in use by another stack: $($conflictingOwners -join ', '). Stop that stack first, then rerun this script."
    }
    Write-Host "Loading the original project's checksum-verified offline images, then starting its stack. No build or network pull is used."
    $importScript = Join-Path $bundle "import_airgap_bundle.ps1"
    if (-not (Test-Path -LiteralPath $importScript)) { throw "Offline bundle loader is missing: $importScript" }
    & $importScript
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "Offline bundle import failed (exit $LASTEXITCODE)." }
    Invoke-Compose -ComposeArgs @("ps")
    Write-Host "Waiting for the three validator APIs inside the Docker network..."
    $probeCode = "import httpx; [httpx.get(u + '/node-info', timeout=1).raise_for_status() for u in ('http://validator1:8001', 'http://validator2:8002', 'http://validator3:8003')]"
    $validatorsReady = $false
    $readinessDeadline = (Get-Date).AddSeconds(90)
    while ((Get-Date) -lt $readinessDeadline) {
        $probeExitCode = Invoke-QuietCompose -ComposeArgs @("exec", "-T", "validator1", "python", "-c", $probeCode)
        if ($probeExitCode -eq 0) {
            $validatorsReady = $true
            break
        }
        Start-Sleep -Seconds 2
    }
    if (-not $validatorsReady) { throw "Validator APIs did not become ready within 90 seconds." }
    Write-Host "All validator APIs are ready."

    $trustCheck = "import os,sys; sys.exit(0 if os.path.isfile('/app/data/trust/validator_trust.json') else 1)"
    $trustExitCode = Invoke-QuietCompose -ComposeArgs @("--profile", "tools", "run", "--rm", "cli", "python", "-c", $trustCheck)
    $hasTrust = ($trustExitCode -eq 0)
    if ($hasTrust) {
        Write-Host "A validator trust roster is already present in the persistent Compose volume."
    } else {
        Write-Host "First run: compare the printed fingerprints via an independent trusted channel."
        Write-Host "For this single-host demo only, typing PIN records the local demo validators; it is not independent identity verification."
        Invoke-Cli -CliArgs @("python", "scripts/bootstrap_validator_trust.py", "--nodes", "http://validator1:8001,http://validator2:8002,http://validator3:8003", "--out", "/app/data/trust/validator_trust.json")
    }
    Wait-ForEnter "Setup and validator trust are ready. Press Enter to enroll/check recipient identities"

    Show-Stage 2 "RECIPIENT IDENTITIES"
    foreach ($recipient in $Recipients) {
        $identityCheck = "from crypto.keys import lookup_identity; lookup_identity('$recipient'); print('Identity already enrolled: $recipient')"
        $identityExitCode = Invoke-QuietCompose -ComposeArgs @("--profile", "tools", "run", "--rm", "cli", "python", "-c", $identityCheck)
        if ($identityExitCode -eq 0) {
            Write-Host "Recipient identity '$recipient' is registered."
        } else {
            Write-Host "Enroll '$recipient'. The passphrase prompt does not echo characters as you type."
            Invoke-Cli -CliArgs @("python", "agent/cli.py", "enroll", "--as", $recipient)
        }
    }
    Wait-ForEnter "Recipient identities are ready. Press Enter to choose the source document"

    Show-Stage 3 "ENCRYPTION"
    if (-not $InputFile) {
        $sample = Join-Path $project "ISRO -Hackathon.pdf"
        if (Test-Path -LiteralPath $sample) {
            $suggestion = Read-Host "Source document path (Enter uses $sample)"
            $InputFile = if ($suggestion) { $suggestion } else { $sample }
        } else {
            $InputFile = Read-Host "Enter the full path to a PDF, Office document, text file, or image"
        }
    }
    $source = (Resolve-Path -LiteralPath $InputFile).Path
    $stagedSource = Join-Path $inputDirectory (Split-Path -Leaf $source)
    Copy-Item -LiteralPath $source -Destination $stagedSource -Force
    $containerSource = "/data/demo-input/$(Split-Path -Leaf $source)"
    $recipientList = $Recipients -join ","
    Write-Host "Encrypting '$source' for: $recipientList"
    Invoke-Cli -CliArgs @("python", "agent/cli.py", "encrypt", "--input", $containerSource, "--recipients", $recipientList, "--out", "/data/package.json")
    Wait-ForEnter "Encrypted package is ready at $dataRoot\package.json. Press Enter to decrypt as $DecryptAs"

    Show-Stage 4 "RECIPIENT DECRYPTION, WATERMARK, SIGNATURE, AND QUORUM"
    Invoke-Cli -CliArgs @("python", "agent/cli.py", "decrypt", "--package", "/data/package.json", "--as", $DecryptAs, "--doc-id", $DocumentId, "--out-dir", "/data/decrypted")
    $markedPdf = Join-Path $outputDirectory "$($DocumentId)_$($DecryptAs).pdf"
    if (-not (Test-Path -LiteralPath $markedPdf)) {
        throw "Marked PDF was not created. Check that decrypt reported Committed: True."
    }

    Show-Stage 5 "TRACE THE MARKED COPY"
    $leakPath = Join-Path $dataRoot "leaked_page.png"
    $containerLeak = "/data/leaked_page.png"
    $renderCode = "import pymupdf; d=pymupdf.open('/data/decrypted/$($DocumentId)_$($DecryptAs).pdf'); d[0].get_pixmap(dpi=150).save('$containerLeak'); print('Wrote $containerLeak')"
    Invoke-Cli -CliArgs @("python", "-c", $renderCode)
    Write-Host "Marked PDF: $markedPdf"
    Write-Host "Demo leaked-page image: $leakPath"
    Write-Host "Trace console: http://localhost:8501"
    try { Start-Process "http://localhost:8501" } catch { Write-Host "Open http://localhost:8501 in your browser." }
    Write-Host "Upload leaked_page.png (or the marked PDF) and download the JSON evidence bundle after the trace verifies."
    Write-Host "The evidence links the recovered copy to a signed decryption-session record; it does not prove who distributed the copy."
    Wait-ForEnter "Demo complete. Press Enter to leave the offline stack running"
}
catch {
    Write-Host "`nDemo stopped: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
