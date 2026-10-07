@echo off
setlocal
set "DIR=%~dp0"
python "%DIR%pre-commit.runner.py" %*
exit /b %ERRORLEVEL%
