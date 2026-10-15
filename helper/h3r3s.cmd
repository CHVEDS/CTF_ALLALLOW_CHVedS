@echo off
chcp 65001 >nul
title h3r3s // CTF helper
setlocal enableextensions
set "SCRIPT=%~dp0h3r3s.py"

rem 1) лаунчер py (ставится вместе с Python с python.org)
py -3 "%SCRIPT%" %* 2>nul && goto :ok

rem 2) python3 из PATH
python3 "%SCRIPT%" %* 2>nul && goto :ok

rem 3) python из PATH, но НЕ заглушка из Microsoft Store (WindowsApps)
for /f "delims=" %%P in ('where python 2^>nul') do (
    echo %%P | find /i "WindowsApps" >nul || ( "%%P" "%SCRIPT%" %* && goto :ok )
)

rem 4) типичные места установки
for %%D in ("%LocalAppData%\Programs\Python" "%ProgramFiles%\Python*" "C:\Python*") do (
    for /f "delims=" %%E in ('dir /b /s "%%~D\python.exe" 2^>nul') do (
        "%%E" "%SCRIPT%" %* && goto :ok
    )
)

echo.
echo   Python не найден.
echo   Запусти install.cmd из папки CTF и поставь набор BASE,
echo   либо скачай Python с https://www.python.org/downloads/
echo   (при установке отметь галочку "Add python.exe to PATH").
echo.

:ok
pause
