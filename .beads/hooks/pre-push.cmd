@echo off
setlocal
set "DIR=%~dp0"
python "%DIR%pre-push.runner.py" %*
exit /b %ERRORLEVEL%
