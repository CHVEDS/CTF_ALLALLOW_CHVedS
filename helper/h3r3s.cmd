@echo off
chcp 65001 >nul
title h3r3s // CTF helper
where py >/dev/null 2>/dev/null && (py "%~dp0h3r3s.py" %*) || (python "%~dp0h3r3s.py" %*)
pause
