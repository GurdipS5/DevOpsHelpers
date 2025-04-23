#!/usr/bin/env pwsh

param(
    [Parameter(Mandatory = $true)]
    [string]$Url,

    [string[]]$Args
)

$scriptPath = "/opt/shcheck/shcheck.py"

# Make sure python3 and pip3 are available
if (-not (Get-Command python3 -ErrorAction SilentlyContinue)) {
    throw "python3 is not installed."
}

if (-not (Test-Path $scriptPath)) {
    throw "shcheck.py not found at $scriptPath"
}

# Run shcheck with Python 3
python3 $scriptPath $Url @Args
