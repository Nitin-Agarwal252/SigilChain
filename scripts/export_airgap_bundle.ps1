param(
    [string]$OutputDirectory = ".\dist\airgap"
)

$ErrorActionPreference = "Stop"
$project = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$requestedOutput = if ([System.IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory
} else {
    Join-Path $project $OutputDirectory
}
$output = [System.IO.Path]::GetFullPath($requestedOutput)
$projectPrefix = $project.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
if (-not $output.StartsWith($projectPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Output directory must stay inside the project directory: $project"
}
New-Item -ItemType Directory -Force -Path $output | Out-Null

Push-Location $project
try {
    docker compose --profile tools build
    if ($LASTEXITCODE -ne 0) { throw "docker compose build failed" }
    docker image inspect quay.io/coreos/etcd:v3.6.15 *> $null
    if ($LASTEXITCODE -ne 0) {
        docker pull quay.io/coreos/etcd:v3.6.15
        if ($LASTEXITCODE -ne 0) { throw "Could not obtain the pinned etcd image" }
    }
    $imageArchive = Join-Path $output "sigilchain-images.tar"
    docker save --output $imageArchive sigilchain-app:local sigilchain-cli:local quay.io/coreos/etcd:v3.6.15
    if ($LASTEXITCODE -ne 0) { throw "docker save failed" }

    Copy-Item (Join-Path $project "docker-compose.yml") $output -Force
    Copy-Item (Join-Path $PSScriptRoot "import_airgap_bundle.ps1") $output -Force
    Copy-Item (Join-Path $project "demo.ps1") $output -Force
    @"
SigilChain air-gapped deployment bundle

1. Copy this complete folder to the isolated Docker host.
2. Run PowerShell in this folder: .\import_airgap_bundle.ps1
3. The stack is available on localhost:8501; validator API ports are internal to Docker.

The bundle contains application/container images and deployment files only. It deliberately
does not contain identity private keys, validator signing keys, local recipient keys, .env
files, or persistent database volumes. After startup, create an identity on each recipient's
machine with `docker compose run --rm cli python agent/cli.py enroll --as RECIPIENT_ID`.
Validator receipts use ML-DSA-65. Then pin the three validator keys after comparing their fingerprints over a trusted channel. If this upgrades a prior Ed25519 demo, the previous trust roster is saved as validator_trust.json.previous for checking older evidence:
`docker compose run --rm cli python scripts/bootstrap_validator_trust.py --nodes http://validator1:8001,http://validator2:8002,http://validator3:8003`.
The CLI stores local private keys under the host's `cli-data` directory; that directory is
not part of this bundle and must remain with the recipient device.

Consensus uses a 3-member etcd/Raft cluster: one unavailable member is tolerated; two are not.
This is crash-fault consensus, not Byzantine consensus. The Compose demo runs all three
members on one host, which remains a single failure domain. Application services use an
internal Docker network with no egress. An opt-in console proxy uses a separate frontend
network and binds only to localhost:8501; on an air-gapped host that network has no
Internet route. Air-gapping does not itself secure the host.
"@ | Set-Content -Encoding UTF8 (Join-Path $output "README-airgap.txt")

    $hash = (Get-FileHash -Algorithm SHA256 $imageArchive).Hash.ToLowerInvariant()
    "$hash  sigilchain-images.tar" | Set-Content -Encoding ASCII (Join-Path $output "SHA256SUMS")
    Write-Host "Air-gap bundle exported to $output"
    Write-Host "Image archive SHA-256: $hash"
}
finally {
    Pop-Location
}
