param([string]$OutputDirectory = ".\dist\airgap")

$ErrorActionPreference = "Stop"
$project = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$requested = if ([IO.Path]::IsPathRooted($OutputDirectory)) { $OutputDirectory } else { Join-Path $project $OutputDirectory }
$output = [IO.Path]::GetFullPath($requested)
$prefix = $project.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $output.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Output directory must stay inside the project directory: $project"
}
New-Item -ItemType Directory -Force -Path $output | Out-Null

Push-Location $project
try {
    docker compose --profile tools build
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose image build failed." }

    docker image inspect quay.io/coreos/etcd:v3.6.15 *> $null
    if ($LASTEXITCODE -ne 0) {
        docker pull quay.io/coreos/etcd:v3.6.15
        if ($LASTEXITCODE -ne 0) { throw "Could not obtain the pinned etcd image." }
    }

    $archive = Join-Path $output "sigilchain-images.tar"
    docker save --output $archive sigilchain-app:local sigilchain-cli:local quay.io/coreos/etcd:v3.6.15
    if ($LASTEXITCODE -ne 0) { throw "Could not export the Docker images." }

    Copy-Item (Join-Path $project "docker-compose.yml") $output -Force
    Copy-Item (Join-Path $PSScriptRoot "import_airgap_bundle.ps1") $output -Force
    @"
SigilChain air-gap bundle

The bundle includes container images and deployment files. It excludes private keys,
recipient identity files, validator signing keys, databases, source documents, packages,
and trust pins. Back up each of those separately and transfer them only through approved
channels.

Before importing, set SIGILCHAIN_API_KEY to the same random secret (at least 32 UTF-8
bytes) configured for authorized clients. Do not put it in this bundle.

1. Copy this folder to the isolated Docker host.
2. Run .\import_airgap_bundle.ps1 in PowerShell from this folder.
3. Check startup with docker compose ps; open http://127.0.0.1:8501 for the trace console.
4. Compare validator fingerprints through an independent trusted channel, then run:
   docker compose --profile tools run --rm cli python scripts/pin_validators.py --nodes http://validator1:8001,http://validator2:8002,http://validator3:8003 --out /data/trust/validator_trust.json
5. Enroll recipients with: docker compose --profile tools run --rm cli python -m sigilchain.cli enroll --as RECIPIENT_ID

The validators use a three-member etcd/Raft group. It tolerates one unavailable member,
not two, and it is crash-fault consensus rather than Byzantine consensus. All members
share one host failure domain in this Compose demo. The application network is internal;
the local console proxy binds only to localhost.
"@ | Set-Content -Encoding UTF8 (Join-Path $output "README-airgap.txt")

    $files = @("sigilchain-images.tar", "docker-compose.yml", "import_airgap_bundle.ps1", "README-airgap.txt")
    $checksums = foreach ($file in $files) {
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $output $file)).Hash.ToLowerInvariant()
        "$hash  $file"
    }
    $checksums | Set-Content -Encoding ASCII (Join-Path $output "SHA256SUMS")
    Write-Host "Air-gap bundle exported to $output"
} finally {
    Pop-Location
}
