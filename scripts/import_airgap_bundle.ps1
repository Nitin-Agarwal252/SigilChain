$ErrorActionPreference = "Stop"
$bundle = (Resolve-Path $PSScriptRoot).Path
$archive = Join-Path $bundle "sigilchain-images.tar"
$checksumFile = Join-Path $bundle "SHA256SUMS"
if (-not (Test-Path -LiteralPath $archive) -or -not (Test-Path -LiteralPath $checksumFile)) {
    throw "Bundle is incomplete: expected sigilchain-images.tar and SHA256SUMS in $bundle"
}
$expected = ((Get-Content -Raw -LiteralPath $checksumFile).Trim() -split "\s+")[0].ToLowerInvariant()
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "Image archive checksum mismatch; refusing to load it." }

docker load --input $archive
if ($LASTEXITCODE -ne 0) { throw "docker load failed" }
docker compose --project-directory $bundle -f (Join-Path $bundle "docker-compose.yml") --profile local-ui up --detach --no-build --pull never
if ($LASTEXITCODE -ne 0) { throw "Could not start SigilChain from the loaded images" }
Write-Host "SigilChain is starting. Check status with: docker compose ps"
Write-Host "Trace console: http://localhost:8501"
