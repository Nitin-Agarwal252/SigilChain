$ErrorActionPreference = "Stop"
$previousApiKey = [Environment]::GetEnvironmentVariable("SIGILCHAIN_API_KEY", "Process")
$env:SIGILCHAIN_API_KEY = "sigilchain-test-only-key-not-for-production-0001"
try {
    docker compose --profile tools run --rm cli python -m unittest discover -s /app/tests -v
    if ($LASTEXITCODE -ne 0) { throw "Core acceptance tests failed" }
    docker compose exec -T validator1 python -m unittest discover -s /app/tests -p test_validator_integration.py -v
    if ($LASTEXITCODE -ne 0) { throw "Validator integration tests failed" }
} finally {
    if ($null -eq $previousApiKey) {
        Remove-Item Env:SIGILCHAIN_API_KEY -ErrorAction SilentlyContinue
    } else {
        $env:SIGILCHAIN_API_KEY = $previousApiKey
    }
}
