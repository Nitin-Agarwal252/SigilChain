$ErrorActionPreference = "Stop"
$bundle = (Resolve-Path $PSScriptRoot).Path
$checksumFile = Join-Path $bundle "SHA256SUMS"
if (-not (Test-Path -LiteralPath $checksumFile)) { throw "Bundle is incomplete: SHA256SUMS is missing" }
$bundleFiles = @("sigilchain-images.tar", "docker-compose.yml", "import_airgap_bundle.ps1", "README-airgap.txt")
$lines = @(Get-Content -LiteralPath $checksumFile)
if ($lines.Count -ne $bundleFiles.Count) { throw "Checksum manifest must contain exactly $($bundleFiles.Count) bundle files" }
$verified = @{}
foreach ($line in $lines) {
    if ($line -notmatch '^([0-9a-fA-F]{64})  ([A-Za-z0-9_.-]+)$') { throw "Malformed checksum manifest line" }
    $name = $Matches[2]
    if (($name -notin $bundleFiles) -or $verified.ContainsKey($name)) { throw "Unexpected or duplicate bundle file: $name" }
    $path = Join-Path $bundle $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Bundle file is missing: $name" }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
    if ($Matches[1].ToLowerInvariant() -ne $actual) { throw "Checksum mismatch: $name" }
    $verified[$name] = $true
}
foreach ($name in $bundleFiles) {
    if (-not $verified.ContainsKey($name)) { throw "Checksum manifest does not cover $name" }
}
$archive = Join-Path $bundle "sigilchain-images.tar"
docker load --input $archive
if ($LASTEXITCODE -ne 0) { throw "docker load failed" }
foreach ($image in @("sigilchain-app:local", "sigilchain-cli:local", "quay.io/coreos/etcd:v3.6.15")) {
    docker image inspect $image *> $null
    if ($LASTEXITCODE -ne 0) { throw "Required image is missing after import: $image" }
}
docker compose --project-directory $bundle -f (Join-Path $bundle "docker-compose.yml") `
    --profile local-ui up --detach --no-build --pull never
if ($LASTEXITCODE -ne 0) { throw "Could not start from imported images" }
Write-Host "SigilChain is starting at http://127.0.0.1:8501"
