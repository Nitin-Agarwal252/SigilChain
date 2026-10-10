$ErrorActionPreference = "Stop"
docker compose --profile tools run --rm cli python -m unittest discover -s /app/tests -v
if ($LASTEXITCODE -ne 0) { throw "Core acceptance tests failed" }
docker compose exec -T validator1 python -m unittest discover -s /app/tests -p test_validator_integration.py -v
if ($LASTEXITCODE -ne 0) { throw "Validator integration tests failed" }
