$ErrorActionPreference = 'Stop'
$runner = Join-Path $PSScriptRoot 'pre-commit.runner.py'
python $runner @args
exit $LASTEXITCODE
