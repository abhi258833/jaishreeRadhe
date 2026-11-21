$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Running AES-256-GCM Cryptographic Assessment Test Suite" -ForegroundColor Cyan
Write-Host "=================================================================`n" -ForegroundColor Cyan

if (-not (Test-Path "target/classes")) {
    New-Item -ItemType Directory -Path "target/classes" -Force | Out-Null
}

Write-Host "[1/2] Compiling Java classes with UTF-8 encoding..." -ForegroundColor Yellow
javac -encoding UTF-8 -d target/classes src/main/java/com/security/crypto/*.java

if ($LASTEXITCODE -ne 0) {
    Write-Host "Compilation failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}
Write-Host "Compilation successful.`n" -ForegroundColor Green

Write-Host "[2/2] Running automated cryptographic verification tests...`n" -ForegroundColor Yellow
java -cp target/classes com.security.crypto.CryptoAssessmentDemo
