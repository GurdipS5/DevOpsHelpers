# Enhanced Vault to Octopus script using built-in Octopus API access
# This version uses Octopus Deploy's built-in API capabilities

param(
    [Parameter(Mandatory=$false)]
    [string]$VaultUrl = $OctopusParameters["Vault.Url"],
    
    [Parameter(Mandatory=$false)]
    [string]$AppRoleId = $OctopusParameters["Vault.AppRoleId"],
    
    [Parameter(Mandatory=$false)]
    [string]$AppSecretId = $OctopusParameters["Vault.AppSecretId"],
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = $OctopusParameters["Vault.SyncConfigPath"]
)

Write-Host "🐙 Enhanced Vault to Octopus Sync (Built-in API)" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green

# Get Octopus connection details from built-in variables
$octopusUrl = $OctopusParameters["Octopus.Web.ServerUri"]
$octopusSpaceId = $OctopusParameters["Octopus.Space.Id"]
$octopusProjectId = $OctopusParameters["Octopus.Project.Id"]

Write-Host "📋 Octopus Connection Details:" -ForegroundColor Cyan
Write-Host "  Server: $octopusUrl"
Write-Host "  Space: $octopusSpaceId"  
Write-Host "  Project: $octopusProjectId"

# Determine API key source (priority order)
$octopusApiKey = $null
$apiKeySource = ""

# 1. Try built-in API key (Octopus 2022.2+)
if ($OctopusParameters["Octopus.Action.BuiltIn.ApiKey"]) {
    $octopusApiKey = $OctopusParameters["Octopus.Action.BuiltIn.ApiKey"]
    $apiKeySource = "Built-in API Key"
}
# 2. Try service account API key
elseif ($OctopusParameters["Octopus.ServiceAccount.ApiKey"]) {
    $octopusApiKey = $OctopusParameters["Octopus.ServiceAccount.ApiKey"]
    $apiKeySource = "Service Account API Key"
}
# 3. Try project-scoped API key
elseif ($OctopusParameters["Project.ApiKey"]) {
    $octopusApiKey = $OctopusParameters["Project.ApiKey"]
    $apiKeySource = "Project-Scoped API Key"
}
# 4. Try worker pool service account
elseif ($OctopusParameters["WorkerPool.ServiceAccount.ApiKey"]) {
    $octopusApiKey = $OctopusParameters["WorkerPool.ServiceAccount.ApiKey"]
    $apiKeySource = "Worker Pool Service Account"
}

if (-not $octopusApiKey) {
    Write-Error "❌ No Octopus API key available. Configure one of:"
    Write-Error "   • Octopus.ServiceAccount.ApiKey (recommended)"
    Write-Error "   • Project.ApiKey (project-scoped)"
    Write-Error "   • WorkerPool.ServiceAccount.ApiKey (worker-scoped)"
    exit 1
}

Write-Host "✅ Using API Key Source: $apiKeySource" -ForegroundColor Green

# Validate Vault parameters
if (-not $VaultUrl -or -not $AppRoleId -or -not $AppSecretId) {
    Write-Error "❌ Missing Vault parameters. Ensure these variables are set:"
    Write-Error "   • Vault.Url"
    Write-Error "   • Vault.AppRoleId" 
    Write-Error "   • Vault.AppSecretId"
    exit 1
}

# Load or use default configuration
if (-not $ConfigPath) {
    $ConfigPath = "./vault-secrets.json"
}

if (-not (Test-Path $ConfigPath)) {
    Write-Warning "⚠️ Configuration file not found: $ConfigPath"
    Write-Host "Creating default configuration..."
    
    # Create default configuration
    $defaultConfig = @{
        secrets = @(
            @{
                name = "Cloudflare API Token"
                vaultPath = "secret/data/cloudflare"
                vaultKey = "api_token"
                octopusVariable = "Cloudflare.ApiToken"
                environmentScope = @("Development", "Staging", "Production")
                isSensitive = $true
                required = $true
                description = "Cloudflare API Token for DNS management"
            },
            @{
                name = "SonarQube Token"
                vaultPath = "secret/data/sonarqube"
                vaultKey = "token"
                octopusVariable = "SonarQube.Token"
                environmentScope = @("Development", "Staging", "Production")
                isSensitive = $true
                required = $true
                description = "SonarQube authentication token"
            }
        )
    }
    
    $defaultConfig | ConvertTo-Json -Depth 5 | Out-File $ConfigPath -Encoding UTF8
    Write-Host "✅ Default configuration created at: $ConfigPath"
}

# Load configuration
try {
    $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    Write-Host "✅ Loaded configuration: $($config.secrets.Count) secrets defined"
} catch {
    Write-Error "❌ Failed to parse configuration file: $($_.Exception.Message)"
    exit 1
}

# Function to authenticate with Vault
function Get-VaultToken {
    param(
        [string]$VaultUrl,
        [string]$RoleId,
        [string]$SecretId
    )
    
    Write-Host "🔐 Authenticating with Vault..." -ForegroundColor Yellow
    
    $authBody = @{
        role_id = $RoleId
        secret_id = $SecretId
    } | ConvertTo-Json
    
    try {
        $authResponse = Invoke-RestMethod -Uri "$VaultUrl/v1/auth/approle/login" -Method Post -Body $authBody -ContentType "application/json"
        Write-Host "✅ Vault authentication successful"
        return $authResponse.auth.client_token
    } catch {
        Write-Error "❌ Vault authentication failed: $($_.Exception.Message)"
        throw
    }
}

# Function to get secret from Vault
function Get-VaultSecret {
    param(
        [string]$VaultUrl,
        [string]$Token,
        [string]$SecretPath,
        [string]$SecretKey
    )
    
    $headers = @{ "X-Vault-Token" = $Token }
    
    try {
        $secretResponse = Invoke-RestMethod -Uri "$VaultUrl/v1/$SecretPath" -Headers $headers
        
        if ($secretResponse.data.data.$SecretKey) {
            return $secretResponse.data.data.$SecretKey
        } elseif ($secretResponse.data.$SecretKey) {
            return $secretResponse.data.$SecretKey
        } else {
            throw "Secret key '$SecretKey' not found"
        }
    } catch {
        Write-Error "❌ Failed to get secret from $SecretPath`: $($_.Exception.Message)"
        throw
    }
}

# Function to update Octopus variable using built-in API
function Set-OctopusVariable {
    param(
        [string]$ApiKey,
        [string]$VariableName,
        [string]$VariableValue,
        [array]$EnvironmentScope = @(),
        [bool]$IsSensitive = $true,
        [string]$Description = ""
    )
    
    Write-Host "🐙 Setting Octopus variable: $VariableName" -ForegroundColor Cyan
    
    $headers = @{
        "X-Octopus-ApiKey" = $ApiKey
        "Content-Type" = "application/json"
    }
    
    try {
        # Get current variable set
        $variableSetUrl = "$octopusUrl/api/$octopusSpaceId/projects/$octopusProjectId/variables"
        $variableSet = Invoke-RestMethod -Uri $variableSetUrl -Headers $headers -Method Get
        
        # Find existing variable
        $existingVariable = $variableSet.Variables | Where-Object { $_.Name -eq $VariableName }
        
        if ($existingVariable) {
            Write-Host "   📝 Updating existing variable"
            $existingVariable.Value = $VariableValue
            $existingVariable.IsSensitive = $IsSensitive
            if ($Description) { $existingVariable.Description = $Description }
        } else {
            Write-Host "   ➕ Creating new variable"
            $newVariable = @{
                Name = $VariableName
                Value = $VariableValue
                IsSensitive = $IsSensitive
                Description = $Description
                Scope = @{
                    Environment = $EnvironmentScope
                }
            }
            $variableSet.Variables += $newVariable
        }
        
        # Update variable set
        $updateBody = $variableSet | ConvertTo-Json -Depth 10
        $updateUrl = "$octopusUrl/api/$octopusSpaceId/variables/$($variableSet.Id)"
        $result = Invoke-RestMethod -Uri $updateUrl -Headers $headers -Method Put -Body $updateBody
        
        Write-Host "   ✅ Variable updated successfully"
        return $result
    } catch {
        Write-Error "❌ Failed to set variable '$VariableName': $($_.Exception.Message)"
        throw
    }
}

# Main execution
try {
    Write-Host ""
    Write-Host "🚀 Starting Vault to Octopus synchronization..." -ForegroundColor Green
    
    # Authenticate with Vault
    $vaultToken = Get-VaultToken -VaultUrl $VaultUrl -RoleId $AppRoleId -SecretId $AppSecretId
    
    $successCount = 0
    $failureCount = 0
    
    # Process each secret
    foreach ($secretConfig in $config.secrets) {
        Write-Host ""
        Write-Host "🔄 Processing: $($secretConfig.name)" -ForegroundColor Yellow
        
        try {
            # Get secret from Vault
            $secretValue = Get-VaultSecret -VaultUrl $VaultUrl -Token $vaultToken -SecretPath $secretConfig.vaultPath -SecretKey $secretConfig.vaultKey
            
            # Set variable in Octopus
            Set-OctopusVariable -ApiKey $octopusApiKey -VariableName $secretConfig.octopusVariable -VariableValue $secretValue -EnvironmentScope $secretConfig.environmentScope -IsSensitive $secretConfig.isSensitive -Description $secretConfig.description
            
            $successCount++
            Write-Host "✅ Successfully synced: $($secretConfig.name)" -ForegroundColor Green
            
        } catch {
            $failureCount++
            Write-Error "❌ Failed to sync '$($secretConfig.name)': $($_.Exception.Message)"
            
            if ($secretConfig.required) {
                Write-Error "💥 Required secret failed, aborting..."
                throw
            } else {
                Write-Warning "⚠️ Optional secret failed, continuing..."
            }
        }
    }
    
    # Clean up Vault token
    try {
        $headers = @{ "X-Vault-Token" = $vaultToken }
        Invoke-RestMethod -Uri "$VaultUrl/v1/auth/token/revoke-self" -Headers $headers -Method Post | Out-Null
        Write-Host "🔒 Vault token revoked" -ForegroundColor Gray
    } catch {
        Write-Warning "⚠️ Failed to revoke Vault token: $($_.Exception.Message)"
    }
    
    Write-Host ""
    Write-Host "🎉 Synchronization completed!" -ForegroundColor Green
    Write-Host "📊 Summary:" -ForegroundColor Cyan
    Write-Host "   ✅ Successful: $successCount"
    Write-Host "   ❌ Failed: $failureCount"
    Write-Host "   🔑 API Key Source: $apiKeySource"
    Write-Host "   🏢 Target Project: $octopusProjectId"
    
} catch {
    Write-Error "💥 Synchronization failed: $($_.Exception.Message)"
    exit 1
}

Write-Host ""
Write-Host "✨ Vault to Octopus sync completed using built-in API access!" -ForegroundColor Green
