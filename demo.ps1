param(
    [string]$InputFile,
    [string[]]$Recipients = @("nitin", "ashish", "rahul_demo"),
    [string]$BranchRecipient = "deepa_demo",
    [string]$DecryptAs,
    [string]$DocumentId = "demo-$(Get-Date -Format yyyyMMdd-HHmmss)",
    [ValidateSet("dct", "dwt-dct")][string]$WatermarkTransform = "dct",
    [switch]$SkipGovernance,
    [string]$BundleDirectory = $(if (Test-Path (Join-Path $PSScriptRoot "sigilchain-images.tar")) { $PSScriptRoot } else { Join-Path $PSScriptRoot "dist\airgap" })
)

$ErrorActionPreference = "Stop"
$project = (Resolve-Path $PSScriptRoot).Path
$bundle = (Resolve-Path $BundleDirectory).Path
$composeFile = Join-Path $bundle "docker-compose.yml"
if (-not (Test-Path -LiteralPath $composeFile)) {
    throw "No offline Compose bundle found at '$bundle'. Run scripts\export_airgap_bundle.ps1 first."
}
if (-not $Recipients -or $Recipients.Count -lt 3) {
    throw "Provide at least three linear-path IDs: sender, first holder, and final recipient."
}
foreach ($recipient in (@($Recipients) + @($BranchRecipient))) {
    if ($recipient -notmatch '^[A-Za-z0-9_.-]{1,64}$') {
        throw "Invalid recipient ID '$recipient'. Use only letters, numbers, dot, underscore, or hyphen."
    }
}
if ($Recipients -contains $BranchRecipient) {
    throw "BranchRecipient must be a separate identity from the linear recipient path."
}
if (-not $DecryptAs) { $DecryptAs = $Recipients[-1] }
if ($DecryptAs -cne $Recipients[-1]) {
    throw "For this demo path, DecryptAs must be the final linear recipient '$($Recipients[-1])'."
}
if ($DocumentId -notmatch '^[A-Za-z0-9._-]{1,80}$') {
    throw "DocumentId may contain only letters, numbers, dot, underscore, and hyphen (max 80 chars)."
}

$dataRoot = Join-Path $bundle "cli-data"
$inputDirectory = Join-Path $dataRoot "demo-input"
$outputDirectory = Join-Path $dataRoot "decrypted"
$governanceDirectory = Join-Path $dataRoot "governance"
$envFile = Join-Path $bundle ".env"
New-Item -ItemType Directory -Force -Path $inputDirectory, $outputDirectory, $governanceDirectory | Out-Null

function Write-Info([string]$Message) { Write-Host "  $Message" -ForegroundColor Gray }
function Write-Action([string]$Message) { Write-Host "  > $Message" -ForegroundColor Cyan }
function Write-Good([string]$Message) { Write-Host "  OK  $Message" -ForegroundColor Green }
function Write-Warn([string]$Message) { Write-Host "  NOTE  $Message" -ForegroundColor Yellow }

function Set-BundleEnvValue {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Value)
    $lines = @()
    if (Test-Path -LiteralPath $envFile) { $lines = @(Get-Content -LiteralPath $envFile) }
    $prefix = [regex]::Escape($Name) + "="
    $lines = @($lines | Where-Object { $_ -notmatch "^\s*$prefix" })
    $lines += "$Name=$Value"
    Set-Content -LiteralPath $envFile -Value $lines -Encoding Ascii
}

function Get-BundleEnvValue([string]$Name) {
    if (-not (Test-Path -LiteralPath $envFile)) { return $null }
    $prefix = [regex]::Escape($Name) + "="
    $match = Get-Content -LiteralPath $envFile | Where-Object { $_ -match "^\s*$prefix" } | Select-Object -Last 1
    if ($match) { return ($match -replace "^\s*$prefix", "") }
    return $null
}

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
    Write-Host "`n============================================================" -ForegroundColor DarkRed
    Write-Host " STAGE $Number OF 7  |  $Title" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor DarkRed
}

function Wait-ForEnter([string]$Message) {
    [void](Read-Host "`n$Message")
}

function Wait-ForValidators {
    Write-Info "Checking that all three validator APIs respond inside Docker..."
    $probeCode = "import httpx; [httpx.get(u + '/node-info', timeout=2).raise_for_status() for u in ('http://validator1:8001', 'http://validator2:8002', 'http://validator3:8003')]"
    $ready = $false
    $deadline = (Get-Date).AddSeconds(90)
    while ((Get-Date) -lt $deadline) {
        $exitCode = Invoke-QuietCompose -ComposeArgs @("exec", "-T", "validator1", "python", "-c", $probeCode)
        if ($exitCode -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 2
    }
    if (-not $ready) { throw "Validator APIs did not become ready within 90 seconds. Check: docker compose logs validator1 validator2 validator3" }
    Write-Good "All three validator APIs are ready."
}

function Enable-GovernanceBaseline {
    Show-Stage 3 "THRESHOLD GOVERNANCE BASELINE"
    Write-Info "Two of three ML-DSA-65 governance keys approve the exact current identity and validator-trust snapshot."
    Write-Warn "For this local demo, the keys are stored on this computer. That demonstrates the approval flow, not independent administrator separation."
    $adminIds = @("demo-admin-a", "demo-admin-b", "demo-admin-c")
    $keyPaths = @(
        (Join-Path $governanceDirectory "demo-admin-a.key.json"),
        (Join-Path $governanceDirectory "demo-admin-b.key.json"),
        (Join-Path $governanceDirectory "demo-admin-c.key.json")
    )
    $publicPaths = @(
        (Join-Path $governanceDirectory "demo-admin-a.pub.json"),
        (Join-Path $governanceDirectory "demo-admin-b.pub.json"),
        (Join-Path $governanceDirectory "demo-admin-c.pub.json")
    )
    $rosterPath = Join-Path $governanceDirectory "governance_roster.json"
    $rosterContainerPath = "/data/governance/governance_roster.json"

    $volumeRosterCheck = "import os,sys; sys.exit(0 if os.path.isfile('/app/data/trust/governance_roster.json') else 1)"
    $hasInstalledRoster = (Invoke-QuietCompose -ComposeArgs @("--profile", "tools", "run", "--rm", "cli", "python", "-c", $volumeRosterCheck)) -eq 0
    if (-not (Test-Path -LiteralPath $rosterPath) -and $hasInstalledRoster) {
        Write-Info "Recovering the already-installed public roster into the local demo folder."
        Invoke-Cli -CliArgs @("python", "-c", "import shutil; shutil.copyfile('/app/data/trust/governance_roster.json','/data/governance/governance_roster.json')")
    }

    if (Test-Path -LiteralPath $rosterPath) {
        foreach ($path in $keyPaths) {
            if (-not (Test-Path -LiteralPath $path)) {
                throw "The installed governance roster already exists, but a matching private key is missing: $path. Restore the original protected key; do not generate a replacement for an installed roster."
            }
        }
        Write-Good "Reusing the installed demo governance roster and its protected keys."
    } else {
        for ($i = 0; $i -lt $adminIds.Count; $i++) {
            if (-not (Test-Path -LiteralPath $keyPaths[$i])) {
                Write-Action "Create protected governance signer $($adminIds[$i]) (use a 12+ character passphrase)."
                Invoke-Cli -CliArgs @("python", "scripts/governance_cli.py", "keygen", "--id", $adminIds[$i], "--out", "/data/governance/$($adminIds[$i]).key.json")
            }
            if (-not (Test-Path -LiteralPath $publicPaths[$i])) {
                throw "The public key matching $($keyPaths[$i]) is missing. Restore its .pub.json file or use a fresh bundle data folder."
            }
        }
        Write-Action "Build a 2-of-3 public governance roster."
        Invoke-Cli -CliArgs @("python", "scripts/governance_cli.py", "roster", "--keys", "/data/governance/demo-admin-a.pub.json", "/data/governance/demo-admin-b.pub.json", "/data/governance/demo-admin-c.pub.json", "--threshold", "2", "--out", $rosterContainerPath)
    }

    Write-Action "Install the roster as the validator governance trust anchor."
    Invoke-Cli -CliArgs @("python", "scripts/governance_cli.py", "install-roster", "--roster", $rosterContainerPath)
    $rosterHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $rosterPath).Hash.ToLowerInvariant()
    $savedHashPath = Join-Path $governanceDirectory "governance_roster.sha256"
    if ((Test-Path -LiteralPath $savedHashPath) -and ((Get-Content -Raw -LiteralPath $savedHashPath).Trim().ToLowerInvariant() -ne $rosterHash)) {
        throw "The governance roster hash changed. Refusing to overwrite the existing pinned value. Verify the roster before proceeding."
    }
    Set-Content -LiteralPath $savedHashPath -Value $rosterHash -Encoding Ascii
    Set-BundleEnvValue -Name "SIGILCHAIN_REQUIRE_GOVERNANCE_APPROVALS" -Value "1"
    Set-BundleEnvValue -Name "SIGILCHAIN_GOVERNANCE_ROSTER_SHA256" -Value $rosterHash
    $env:SIGILCHAIN_REQUIRE_GOVERNANCE_APPROVALS = "1"
    $env:SIGILCHAIN_GOVERNANCE_ROSTER_SHA256 = $rosterHash
    Write-Good "Pinned governance roster SHA-256: $rosterHash"

    Write-Action "Restart validators with governance enforcement enabled."
    Invoke-Compose -ComposeArgs @("up", "-d", "--force-recreate", "validator1", "validator2", "validator3", "console")
    Wait-ForValidators

    Write-Action "Capture the pre-demo identity and validator-trust state as a baseline proposal."
    Invoke-Cli -CliArgs @("python", "scripts/governance_cli.py", "snapshot", "--out", "/data/governance/state-snapshot.json")
    foreach ($admin in @("demo-admin-a", "demo-admin-b")) {
        Write-Action "$admin reviews and signs the same snapshot."
        Invoke-Cli -CliArgs @("python", "scripts/governance_cli.py", "approve", "--action", "/data/governance/state-snapshot.json", "--key", "/data/governance/$admin.key.json", "--out", "/data/governance/$admin.snapshot-approval.json")
    }
    Invoke-Cli -CliArgs @("python", "scripts/governance_cli.py", "merge", "--action", "/data/governance/state-snapshot.json", "--approvals", "/data/governance/demo-admin-a.snapshot-approval.json", "/data/governance/demo-admin-b.snapshot-approval.json", "--out", "/data/governance/snapshot-approvals.json")
    Invoke-Cli -CliArgs @("python", "scripts/governance_cli.py", "verify", "--action", "/data/governance/state-snapshot.json", "--approvals", "/data/governance/snapshot-approvals.json", "--roster", $rosterContainerPath)
    Write-Action "Submit the approved baseline to the validator quorum."
    Invoke-Cli -CliArgs @("python", "scripts/governance_cli.py", "apply", "--action", "/data/governance/state-snapshot.json", "--approvals", "/data/governance/snapshot-approvals.json", "--roster", $rosterContainerPath)
    Write-Good "The baseline is quorum-committed. Future governed state is checked against this log."
}

try {
    $existingGovernance = Get-BundleEnvValue "SIGILCHAIN_REQUIRE_GOVERNANCE_APPROVALS"
    $governanceAlreadyEnabled = $existingGovernance -eq "1"
    if ($SkipGovernance -and $existingGovernance -eq "1") {
        throw "Governance has already been enabled for this persistent stack. Do not disable it; rerun without -SkipGovernance and retain the pinned roster hash."
    }

    # Compose reads this file on every invocation. Persist the selected transform
    # so the CLI embedder and console extractor use the same mode across shells.
    Set-BundleEnvValue -Name "SIGILCHAIN_WATERMARK_TRANSFORM" -Value $WatermarkTransform
    $env:SIGILCHAIN_WATERMARK_TRANSFORM = $WatermarkTransform

    Show-Stage 1 "START THE LOCAL STACK AND CHECK VALIDATOR TRUST"
    $portOwners = @(& docker ps --filter "publish=8501" --format "{{.Names}}")
    if ($LASTEXITCODE -ne 0) { throw "Docker is unavailable. Start Docker Desktop, then rerun this script." }
    $expectedPrefix = "$(Split-Path -Leaf $bundle)-"
    $conflictingOwners = @($portOwners | Where-Object { $_ -and -not $_.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase) })
    if ($conflictingOwners.Count -gt 0) {
        throw "Port 8501 is in use by another stack: $($conflictingOwners -join ', '). Stop that stack first, then rerun this script."
    }
    Write-Info "The bundle loader verifies the image archive checksum and starts prebuilt images; it does not build or pull images."
    $importScript = Join-Path $bundle "import_airgap_bundle.ps1"
    if (-not (Test-Path -LiteralPath $importScript)) { throw "Offline bundle loader is missing: $importScript" }
    & $importScript
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "Offline bundle import failed (exit $LASTEXITCODE)." }
    Invoke-Compose -ComposeArgs @("ps")
    Wait-ForValidators

    $trustCheck = "import os,sys; sys.exit(0 if os.path.isfile('/app/data/trust/validator_trust.json') else 1)"
    $trustExitCode = Invoke-QuietCompose -ComposeArgs @("--profile", "tools", "run", "--rm", "cli", "python", "-c", $trustCheck)
    if ($trustExitCode -eq 0) {
        Write-Good "A validator trust roster is already present."
    } else {
        Write-Warn "First run: compare all three fingerprints through an independent trusted channel if available."
        Write-Warn "Typing PIN without that channel is local demo setup, not independent validator identity verification."
        Invoke-Cli -CliArgs @("python", "scripts/bootstrap_validator_trust.py", "--nodes", "http://validator1:8001,http://validator2:8002,http://validator3:8003", "--out", "/app/data/trust/validator_trust.json")
    }

    Show-Stage 2 "ENROLL THE PEOPLE IN THE TRANSFER PATH"
    $allRecipients = @($Recipients) + @($BranchRecipient)
    foreach ($recipient in $allRecipients) {
        $identityCheck = "from crypto.keys import lookup_identity; lookup_identity('$recipient'); print('Identity already enrolled: $recipient')"
        $identityExitCode = Invoke-QuietCompose -ComposeArgs @("--profile", "tools", "run", "--rm", "cli", "python", "-c", $identityCheck)
        if ($identityExitCode -eq 0) {
            Write-Good "'$recipient' is already enrolled."
        } else {
            if ($governanceAlreadyEnabled) {
                throw "'$recipient' is not enrolled and governance is already enforced. Approve and apply an identity.enroll change first, or use an already enrolled ID. The demo will not bypass the governance gate."
            }
            Write-Action "Enroll '$recipient'. Enter a passphrase and remember it; typed characters stay hidden."
            Invoke-Cli -CliArgs @("python", "agent/cli.py", "enroll", "--as", $recipient)
        }
    }
    Write-Info "The first ID sends the source; the second ID is the branching holder; later IDs receive the onward packages."
    Write-Warn "If a recipient passphrase was forgotten, use a new ID. The old private key cannot be recovered."
    Wait-ForEnter "Identities are ready. Press Enter to set up the governance demonstration"

    if (-not $SkipGovernance) {
        Enable-GovernanceBaseline
    } else {
        Show-Stage 3 "GOVERNANCE SKIPPED BY REQUEST"
        Write-Warn "The transfer demo will run, but it will not exercise threshold governance approvals or state replay."
    }

    Show-Stage 4 "ENCRYPT THE DOCUMENT AND RECORD THE HANDOFF BRANCHES"
    if (-not $InputFile) {
        $sample = Join-Path $project "ISRO -Hackathon.pdf"
        if (Test-Path -LiteralPath $sample) {
            $suggestion = Read-Host "Source document path (press Enter for $sample)"
            $InputFile = if ($suggestion) { $suggestion } else { $sample }
        } else {
            $InputFile = Read-Host "Enter the full path to a PDF, Office document, text file, or image"
        }
    }
    $source = (Resolve-Path -LiteralPath $InputFile).Path
    $stagedSource = Join-Path $inputDirectory (Split-Path -Leaf $source)
    Copy-Item -LiteralPath $source -Destination $stagedSource -Force
    $containerSource = "/data/demo-input/$(Split-Path -Leaf $source)"
    Write-Info "The source is normalized to PDF. The original file is left untouched."
    Write-Info "Package: ML-KEM-768 + HKDF-SHA256 + AES-256-GCM; ML-DSA-65 signs the manifest and events."
    Write-Info "Watermark mode: $WatermarkTransform (choose dwt-dct to show the optional combined transform)."
    Write-Info "A transfer offer is released only after the validator quorum commits it. The receiving holder signs acceptance of the exact package when forwarding."
    $firstHolder = $Recipients[1]
    Write-Action "Record first transfer: $($Recipients[0]) -> $firstHolder"
    Invoke-Cli -CliArgs @("python", "agent/cli.py", "transfer", "--input", $containerSource, "--from", $Recipients[0], "--to", $firstHolder, "--doc-id", $DocumentId, "--out", "/data/package-$firstHolder.json")

    for ($i = 1; $i -lt ($Recipients.Count - 1); $i++) {
        $fromId = $Recipients[$i]
        $toId = $Recipients[$i + 1]
        Write-Action "Forward accepted package: $fromId -> $toId"
        Invoke-Cli -CliArgs @("python", "agent/cli.py", "transfer", "--package", "/data/package-$fromId.json", "--from", $fromId, "--to", $toId, "--doc-id", $DocumentId, "--out", "/data/package-$toId.json", "--session-out-dir", "/data/decrypted/${fromId}-session")
    }

    Write-Action "Create a second branch from the same accepted package: $firstHolder -> $BranchRecipient"
    Invoke-Cli -CliArgs @("python", "agent/cli.py", "transfer", "--package", "/data/package-$firstHolder.json", "--from", $firstHolder, "--to", $BranchRecipient, "--doc-id", $DocumentId, "--out", "/data/package-$BranchRecipient.json", "--session-out-dir", "/data/decrypted/$firstHolder-branch-session")
    Write-Good "The log now contains separate downstream offers. They share the accepted parent, but neither branch overwrites the other."
    Wait-ForEnter "Both branches are recorded. Press Enter to decrypt as $DecryptAs and $BranchRecipient"

    Show-Stage 5 "DECRYPT, WATERMARK, SIGN, AND COMMIT"
    Write-Info "Each recipient uses their own local private key and passphrase. The marked PDF is released only after quorum commit."
    Invoke-Cli -CliArgs @("python", "agent/cli.py", "decrypt", "--package", "/data/package-$DecryptAs.json", "--as", $DecryptAs, "--doc-id", $DocumentId, "--out-dir", "/data/decrypted/$DecryptAs")
    $finalPdf = Join-Path $outputDirectory "$DecryptAs\$DocumentId`_$DecryptAs.pdf"
    if (-not (Test-Path -LiteralPath $finalPdf)) { throw "Marked PDF missing for '$DecryptAs'. Check that decrypt reported Committed: True." }
    Invoke-Cli -CliArgs @("python", "agent/cli.py", "decrypt", "--package", "/data/package-$BranchRecipient.json", "--as", $BranchRecipient, "--doc-id", $DocumentId, "--out-dir", "/data/decrypted/$BranchRecipient")
    $branchPdf = Join-Path $outputDirectory "$BranchRecipient\$DocumentId`_$BranchRecipient.pdf"
    if (-not (Test-Path -LiteralPath $branchPdf)) { throw "Marked PDF missing for branch recipient '$BranchRecipient'." }
    Write-Good "Both recipients have separate committed, session-marked PDFs. Check each CLI result for Committed: True and etcd-raft."

    if (-not $SkipGovernance) {
        Show-Stage 6 "SEAL AND VERIFY AN EXTERNAL LEDGER CHECKPOINT"
        Write-Info "A checkpoint records the current quorum-agreed ledger head. Keep the sealed file outside this host to detect a later rollback behind it."
        Invoke-Cli -CliArgs @("python", "scripts/checkpoint_cli.py", "capture", "--out", "/data/governance/checkpoint-action.json")
        foreach ($admin in @("demo-admin-a", "demo-admin-b")) {
            Write-Action "$admin approves the exact captured checkpoint."
            Invoke-Cli -CliArgs @("python", "scripts/governance_cli.py", "approve", "--action", "/data/governance/checkpoint-action.json", "--key", "/data/governance/$admin.key.json", "--out", "/data/governance/$admin.checkpoint-approval.json")
        }
        Invoke-Cli -CliArgs @("python", "scripts/governance_cli.py", "merge", "--action", "/data/governance/checkpoint-action.json", "--approvals", "/data/governance/demo-admin-a.checkpoint-approval.json", "/data/governance/demo-admin-b.checkpoint-approval.json", "--out", "/data/governance/checkpoint-approvals.json")
        Invoke-Cli -CliArgs @("python", "scripts/checkpoint_cli.py", "seal", "--action", "/data/governance/checkpoint-action.json", "--approvals", "/data/governance/checkpoint-approvals.json", "--roster", "/data/governance/governance_roster.json", "--out", "/data/governance/checkpoint.json")
        Invoke-Cli -CliArgs @("python", "scripts/checkpoint_cli.py", "verify", "--checkpoint", "/data/governance/checkpoint.json", "--roster", "/data/governance/governance_roster.json")
        Write-Good "Checkpoint verified. Copy this file and the roster to a separately controlled location: $(Join-Path $governanceDirectory 'checkpoint.json')"
    } else {
        Show-Stage 6 "CHECKPOINT SKIPPED"
        Write-Warn "No governance keys were configured, so no threshold-signed checkpoint was produced."
    }

    Show-Stage 7 "TRACE $firstHolder'S MARKED COPY AND EXPORT EVIDENCE"
    $holderSessionDirectory = Join-Path $outputDirectory "$firstHolder-session"
    $holderPdf = Get-ChildItem -LiteralPath $holderSessionDirectory -Filter "$DocumentId`_$firstHolder`_*.pdf" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $holderPdf) {
        $holderSessionDirectory = Join-Path $outputDirectory "$firstHolder-branch-session"
        $holderPdf = Get-ChildItem -LiteralPath $holderSessionDirectory -Filter "$DocumentId`_$firstHolder`_*.pdf" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    }
    if (-not $holderPdf) { throw "Could not find the first holder's marked PDF in $holderSessionDirectory" }
    $leakPath = Join-Path $dataRoot "leaked_page.png"
    $outputRoot = $outputDirectory.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $holderRelativePath = $holderPdf.FullName.Substring($outputRoot.Length).TrimStart([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar).Replace("\", "/")
    $containerHolderPdf = "/data/decrypted/$holderRelativePath"
    $renderCode = "import pymupdf; d=pymupdf.open('$containerHolderPdf'); d[0].get_pixmap(dpi=150).save('/data/leaked_page.png'); print('Wrote /data/leaked_page.png')"
    Invoke-Cli -CliArgs @("python", "-c", $renderCode)
    Write-Info "Upload this $firstHolder session image or marked PDF: $leakPath or $($holderPdf.FullName)"
    Write-Info "Trace console: http://localhost:8501"
    Write-Info "The expected result links the watermark to the first holder's signed session and displays the recorded branch trail."
    Write-Warn "This is key/session evidence; it does not prove which human distributed the file."
    if (-not $SkipGovernance) {
        Write-Info "Governance artifacts are in: $governanceDirectory"
        Write-Info "Copy checkpoint.json and governance_roster.json elsewhere after the demo; local copies do not independently protect against this host."
    }
    Write-Warn "OIDC requires a configured identity provider and fresh token. TPM requires an independent TPM quote verifier; neither is simulated by this local run."
    try { Start-Process "http://localhost:8501" } catch { Write-Info "Open http://localhost:8501 in a browser." }
    Wait-ForEnter "Demo complete. Download the JSON evidence bundle from the console. Press Enter to leave the stack running"
}
catch {
    Write-Host "`nDEMO STOPPED: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
