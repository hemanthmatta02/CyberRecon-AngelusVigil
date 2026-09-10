$ErrorActionPreference = "Stop"

Write-Host "Starting CyberRecon + CyberSentinel..." -ForegroundColor Cyan
docker compose up -d --build

Write-Host ""
Write-Host "Frontend:  http://localhost:46969" -ForegroundColor Green
Write-Host "API Docs:  http://localhost:36969/docs" -ForegroundColor Green
Write-Host "Health:    http://localhost:36969/health" -ForegroundColor Green
Write-Host ""
docker compose ps
