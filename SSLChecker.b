#!/usr/bin/env pwsh

param(
    [Parameter(Mandatory = $true)]
    [string]$Target,

    [string[]]$Args
)

$scriptPath = "/opt/testssl.sh/testssl.sh"

chmod +x $scriptPath

& $scriptPath $Target @Args
