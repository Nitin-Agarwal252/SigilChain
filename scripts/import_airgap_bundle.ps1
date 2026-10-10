$ErrorActionPreference = "Stop"
$bundle = (Resolve-Path $PSScriptRoot).Path
$archive = Join-Path $bundle "sigilchain-images.tar"
$checksumFile = Join-Path $bundle "SHA256SUMS"
if (-not (Test-Path -LiteralPath $archive) -or -not (Test-Path -LiteralPath $checksumFile)) { throw "Bundle is incomplete" }
$expected = ((Get-Content -Raw -LiteralPath $checksumFile).Trim() -split "\s+")[0].ToLowerInvariant()
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
if ($expected -ne $actual) { throw "Image archive checksum mismatch" }
docker load --input $archive
if ($LASTEXITCODE -ne 0) { throw "docker load failed" }
docker compose --project-directory $bundle -f (Join-Path $bundle "docker-compose.yml") `
    --profile local-ui up --detach --no-build --pull never
if ($LASTEXITCODE -ne 0) { throw "Could not start from imported images" }
Write-Host "SigilChain is starting at http://127.0.0.1:8501"
