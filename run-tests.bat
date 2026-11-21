@echo off
chcp 65001 >nul
echo =================================================================
echo  Running AES-256-GCM Cryptographic Assessment Test Suite
echo =================================================================
echo.

if not exist target\classes mkdir target\classes

echo [1/2] Compiling Java classes with UTF-8 encoding...
javac -encoding UTF-8 -d target\classes src\main\java\com\security\crypto\*.java
if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed!
    exit /b %ERRORLEVEL%
)
echo Compilation successful.
echo.

echo [2/2] Running automated cryptographic verification tests...
echo.
java -cp target\classes com.security.crypto.CryptoAssessmentDemo

echo.
pause
