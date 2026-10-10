param([string]$OutputDirectory = ".\dist\airgap")
$ErrorActionPreference = "Stop"
$project = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$requested = if ([IO.Path]::IsPathRooted($OutputDirectory)) { $OutputDirectory } else { Join-Path $project $OutputDirectory }
$output = [IO.Path]::GetFullPath($requested)
$prefix = $project.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $output.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw "Output must be inside $project" }
New-Item -ItemType Directory -Force -Path $output | Out-Null
Push-Location $project
try {
    docker compose --profile tools build
    if ($LASTEXITCODE -ne 0) { throw "Docker image build failed" }
    if (-not (docker image inspect quay.io/coreos/etcd:v3.6.15 2>$null)) {
        docker pull quay.io/coreos/etcd:v3.6.15
        if ($LASTEXITCODE -ne 0) { throw "Could not obtain the pinned etcd image" }
    }
    $archive = Join-Path $output "sigilchain-images.tar"
    docker save --output $archive sigilchain-app:local sigilchain-cli:local quay.io/coreos/etcd:v3.6.15
    if ($LASTEXITCODE -ne 0) { throw "Could not export images" }
    Copy-Item (Join-Path $project "docker-compose.yml") $output -Force
    Copy-Item (Join-Path $PSScriptRoot "import_airgap_bundle.ps1") $output -Force
    @"
SigilChain air-gap bundle. The bundle does not include private keys, local databases,
recipient packages, source documents, or validator trust pins.

1. Verify and load images by running .\import_airgap_bundle.ps1 on the isolated host.
2. Start the stack only from imported images (the importer uses --no-build --pull never).
3. Confirm validator fingerprints over an independent trusted channel, then pin them.
4. Create or import recipient identities and retain recipient private keys on their devices.

The three-member etcd/Raft group tolerates one unavailable member, not a malicious
majority. It is crash-fault consensus, not Byzantine consensus. All Compose members
share one host failure domain. Event times are local clock claims.
"@ | Set-Content -Encoding UTF8 (Join-Path $output "README-airgap.txt")
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    "$hash  sigilchain-images.tar" | Set-Content -Encoding ASCII (Join-Path $output "SHA256SUMS")
    Write-Host "Exported air-gap bundle to $output"
} finally { Pop-Location }
