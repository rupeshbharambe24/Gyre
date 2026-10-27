@echo off
REM ==========================================================================
REM  Gyre - one-click local launcher (Windows)
REM  Double-click this file. It builds Gyre, starts the guarded "Shield" relay
REM  + a hidden origin on your machine, opens the live dashboard, and shows you
REM  how to use it. Close the relay window (or this one) to stop.
REM  To make it reachable from the internet, see docs\DEPLOY.md
REM ==========================================================================
setlocal
cd /d "%~dp0"

set RELAY=127.0.0.1:9500
set DASH=127.0.0.1:9600
set COOKIE=gyre-local-demo
set BIN=target\release

echo.
echo   GYRE - local launcher
echo.

where cargo >nul 2>nul
if errorlevel 1 (
  echo   Rust/cargo is not installed. It's free - get it from https://rustup.rs
  echo   Then re-run this file.
  pause
  exit /b 1
)

echo   Building Gyre (the first build takes a few minutes; later runs are instant)...
cargo build --release -p gyre-cli
if errorlevel 1 (
  echo   Build failed - see the errors above.
  pause
  exit /b 1
)

REM Start the guarded relay (with live dashboard) and a hidden origin in their own windows.
start "gyre-relay"  "%BIN%\gyre-rendezvous.exe" --listen %RELAY% --dashboard %DASH% --capacity 256 --stats-secs 15
timeout /t 2 >nul
start "gyre-origin" "%BIN%\gyre-origin.exe" --rendezvous %RELAY% --cookie %COOKIE% --reply "hello from your hidden origin"
timeout /t 1 >nul
start "" http://%DASH%/

echo.
echo   Gyre is LIVE on your machine.
echo       Dashboard : http://%DASH%/   (should have opened in your browser)
echo       Relay     : %RELAY%   - guarded, proof-of-work admission
echo       Hidden origin parked behind cookie "%COOKIE%"
echo.
echo   Try it in another terminal:
echo       reach it: %BIN%\gyre-reach.exe --rendezvous %RELAY% --cookie %COOKIE% --message hello
echo       flood it: %BIN%\gyre-reach.exe --rendezvous %RELAY% --flood 200    (watch the dashboard)
echo.
echo   Close the "gyre-relay" window to stop Gyre.
pause
endlocal
