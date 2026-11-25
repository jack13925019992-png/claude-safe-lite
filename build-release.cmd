@echo off
setlocal EnableDelayedExpansion

REM ============================================================================
REM Claude Safe Lite v2 - Windows 11 x64 (MinGW/GNU) One-Click Release Builder
REM Rules: Fixed PATH, disk build log, physical memory monitor (recommend >=4GB)
REM ============================================================================

cd /d "%~dp0"

REM 1. Lock toolchain PATH (MinGW64 + Cargo + Node)
set "MINGW_BIN=%USERPROFILE%\msys64\mingw64\bin"
if exist "C:\msys64\mingw64\bin\gcc.exe" (
    if not exist "%MINGW_BIN%\gcc.exe" set "MINGW_BIN=C:\msys64\mingw64\bin"
)
set "CARGO_BIN=%USERPROFILE%\.cargo\bin"
set "PATH=%MINGW_BIN%;%CARGO_BIN%;C:\Program Files\nodejs;%APPDATA%\npm;%SystemRoot%\system32;%SystemRoot%;%SystemRoot%\System32\Wbem;%SystemRoot%\System32\WindowsPowerShell\v1.0"

REM 2. Prepare build-logs directory and timestamped log file
if not exist "build-logs" mkdir "build-logs"
for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd-HHmmss"') do set "BUILD_TS=%%i"
set "LOG_FILE=%~dp0build-logs\build-release-%BUILD_TS%.log"

echo [INFO] Build started at: %DATE% %TIME% > "%LOG_FILE%"
echo [INFO] Log file        : %LOG_FILE%
echo [INFO] Toolchain PATH  : %PATH% >> "%LOG_FILE%"

REM 3. Check available physical memory (warn if < 4096 MB)
for /f %%m in ('powershell -NoProfile -Command "[math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1024)"') do set "FREE_MEM_MB=%%m"
echo [INFO] Free Physical Memory: %FREE_MEM_MB% MB
echo [INFO] Free Physical Memory: %FREE_MEM_MB% MB >> "%LOG_FILE%"

if %FREE_MEM_MB% LSS 4096 (
    echo [WARN] Available memory is below 4096 MB ^(%FREE_MEM_MB% MB^). Close heavy apps if ld runs low on RAM.
    echo [WARN] Available memory below 4096 MB: %FREE_MEM_MB% MB >> "%LOG_FILE%"
)

REM 4. Verify Cargo.toml red-line settings (lto = "thin", codegen-units = 4, cdylib)
findstr /C:"lto = \"thin\"" "src-tauri\Cargo.toml" >nul
if errorlevel 1 (
    echo [ERROR] Cargo.toml missing lto = "thin"! Aborting.
    exit /b 1
)
findstr /C:"codegen-units = 4" "src-tauri\Cargo.toml" >nul
if errorlevel 1 (
    echo [ERROR] Cargo.toml missing codegen-units = 4! Aborting.
    exit /b 1
)
findstr /C:"cdylib" "src-tauri\Cargo.toml" >nul
if errorlevel 1 (
    echo [ERROR] Cargo.toml missing cdylib! Aborting.
    exit /b 1
)

REM 5. Install frontend dependencies if node_modules is absent
if not exist "node_modules" (
    echo [STEP 1/2] Installing frontend dependencies...
    call npm install >> "%LOG_FILE%" 2>&1
    if errorlevel 1 (
        echo [ERROR] npm install failed. Check log: %LOG_FILE%
        exit /b 1
    )
)

REM 6. Start background memory sampler (writes to separate .mem.log to avoid file lock contention)
set "MEM_LOG_FILE=%~dp0build-logs\build-mem-%BUILD_TS%.log"
start /b "" powershell -NoProfile -Command "Start-Sleep -Seconds 5; $idle = 0; while ($idle -lt 4) { if (Get-Process cargo,rustc,ld,makensis,light -ErrorAction SilentlyContinue) { $idle = 0; $mb = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1024); Add-Content -Path '%MEM_LOG_FILE%' -Value ('[MEM-MONITOR] ' + (Get-Date -Format HH:mm:ss) + ' FreePhysicalMemory=' + $mb + 'MB') } else { $idle++ }; Start-Sleep -Seconds 5 }"

REM 7. Execute Tauri Release build and installer bundling (stream live output to console + log file)
echo [STEP 2/2] Running Tauri Release build ^(thin LTO, codegen-units=4^)...
powershell -NoProfile -Command "cmd /c 'npx.cmd tauri build 2>&1' | Tee-Object -FilePath '%LOG_FILE%' -Append; exit $LASTEXITCODE"
if errorlevel 1 (
    echo [ERROR] Tauri release build failed! See log: %LOG_FILE%
    exit /b 1
)

if not exist "src-tauri\target\release\claude-safe-lite.exe" (
    echo [ERROR] Expected binary src-tauri\target\release\claude-safe-lite.exe not found!
    exit /b 1
)

REM 8. Stage clean standalone single-file portable EXE into release-portable\
if not exist "release-portable" mkdir "release-portable"
copy /Y "src-tauri\target\release\claude-safe-lite.exe" "release-portable\claude-safe-lite.exe" >nul

echo [SUCCESS] Release build completed successfully!
echo [SUCCESS] Single-File Portable EXE : release-portable\claude-safe-lite.exe
echo [SUCCESS] Cargo Release EXE        : src-tauri\target\release\claude-safe-lite.exe
echo [SUCCESS] Installer Bundles        : src-tauri\target\release\bundle\
echo [SUCCESS] Build Log                : %LOG_FILE%
echo [INFO] Build finished at: %DATE% %TIME% >> "%LOG_FILE%"
exit /b 0
