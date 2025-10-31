@echo off
REM FireShark Start Script
REM Usage: Double-click or run from terminal
REM Prompts for platform, defaults to Windows

set /p PLATFORM=Choose platform ([W]indows, [L]inux/Mac, [P]owerShell) [W]: 
if "%PLATFORM%"=="" set PLATFORM=W
set PLATFORM=%PLATFORM:~0,1%

if /I "%PLATFORM%"=="W" goto :windows
if /I "%PLATFORM%"=="L" goto :linux
if /I "%PLATFORM%"=="P" goto :powershell

echo Invalid option. Exiting.
goto :eof

:windows
call fires_env\Scripts\activate
start cmd /k "uvicorn app.app:app --reload --host 127.0.0.1 --port 8000"
start cmd /k "python -m http.server 8080"
start http://localhost:8080/upload.html
echo FireShark backend and frontend started! [Windows]
pause
goto :eof

:linux
bash -c "source fires_env/bin/activate; uvicorn app.app:app --reload --host 127.0.0.1 --port 8000 & python3 -m http.server 8080 & xdg-open http://localhost:8080/upload.html"
echo FireShark backend and frontend started! [Linux/Mac]
pause
goto :eof

:powershell
start powershell -NoExit -Command "& fires_env\Scripts\Activate.ps1; uvicorn app.app:app --reload --host 127.0.0.1 --port 8000"
start powershell -NoExit -Command "& fires_env\Scripts\Activate.ps1; python -m http.server 8080"
start http://localhost:8080/upload.html
echo FireShark backend and frontend started! [PowerShell]
pause
goto :eof
