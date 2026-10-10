$ErrorActionPreference = "Stop"
$bundle = (Resolve-Path $PSScriptRoot).Path
if ([string]::IsNullOrWhiteSpace($env:SIGILCHAIN_API_KEY) -or
    [Text.Encoding]::UTF8.GetByteCount($env:SIGILCHAIN_API_KEY) -lt 32) {
    throw "Set SIGILCHAIN_API_KEY to a secret of at least 32 UTF-8 bytes before importing."
}

$files = @("sigilchain-images.tar", "docker-compose.yml", "import_airgap_bundle.ps1", "README-airgap.txt")
$manifest = Join-Path $bundle "SHA256SUMS"
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw "Bundle is missing SHA256SUMS." }
$lines = @(Get-Content -LiteralPath $manifest)
if ($lines.Count -ne $files.Count) { throw "Checksum manifest must cover exactly the four bundle files." }
$verified = @{}
foreach ($line in $lines) {
    if ($line -notmatch '^([0-9a-fA-F]{64})  ([A-Za-z0-9_.-]+)$') { throw "Malformed checksum manifest line." }
    $expected = $Matches[1].ToLowerInvariant()
    $name = $Matches[2]
    if (($name -notin $files) -or $verified.ContainsKey($name)) { throw "Unexpected or duplicate bundle file: $name" }
    $path = Join-Path $bundle $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Bundle file is missing: $name" }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw "Checksum mismatch: $name" }
    $verified[$name] = $true
}
foreach ($name in $files) {
    if (-not $verified.ContainsKey($name)) { throw "Checksum manifest does not cover $name" }
}

docker load --input (Join-Path $bundle "sigilchain-images.tar")
if ($LASTEXITCODE -ne 0) { throw "docker load failed." }
foreach ($image in @("sigilchain-app:local", "sigilchain-cli:local", "quay.io/coreos/etcd:v3.6.15")) {
    docker image inspect $image *> $null
    if ($LASTEXITCODE -ne 0) { throw "Required image is missing after import: $image" }
}
docker compose --project-directory $bundle -f (Join-Path $bundle "docker-compose.yml") `
    --profile local-ui up --detach --no-build --pull never
if ($LASTEXITCODE -ne 0) { throw "Could not start SigilChain using imported images only." }
Write-Host "SigilChain is starting at http://127.0.0.1:8501"
