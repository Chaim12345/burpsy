$ErrorActionPreference = 'Stop'
$runner = Join-Path $PSScriptRoot 'pre-push.runner.py'
python $runner @args
exit $LASTEXITCODE
