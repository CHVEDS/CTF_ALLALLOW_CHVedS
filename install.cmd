@echo off
rem Запуск CTF KIT без возни с ExecutionPolicy. Можно просто дважды кликнуть.
chcp 65001 >nul
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
