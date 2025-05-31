# App Role Management Script for Octopus Deploy
# Manages App Role creation, rotation, and monitoring

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Create", "Rotate", "Status", "Test", "Cleanup")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$VaultUrl = "https://vault.gssira.com",
    
    [Parameter(Mandatory=$false)]
    [string]$RoleName = "octopus-dnscontrol",
    
    [Parameter(Mandatory=$false)]
    [string]$OctopusUrl = "https://octopus.gssira.com",
    
    [Parameter(Mandatory=$false)]
    [string]$OctopusApiKey,
    
    [Parameter(Mandatory=$false)]
    [string]$OctopusSpaceId = "Spaces-1",
    
    [Parameter(Mandatory=$false)]
    [string]$OctopusProjectName = "DNSControl"
)

# Function to authenticate with Vault using LDAP
function Get-VaultTokenInteractive {
    param([string]$VaultUrl)
    
    Write-Host "🔐 Vault LDAP Authentication Required" -ForegroundColor Yellow
    $username = Read-Host "Enter LDAP username"
    $password = Read-Host "Enter LDAP password" -AsSecureString
    
    $passwordText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
    
    $authBody = @{ password = $passwordText } | ConvertTo-Json
    
    try {
        $response = Invoke-RestMethod -Uri "$VaultUrl/v1/auth/ldap/login/$username" -Method Post -Body $authBody -ContentType "application/json"
        Write-Host "✅ LDAP authentication successful" -ForegroundColor Green
        return $response.auth.client_token
    } catch {
        Write-Error "❌ LDAP authentication failed: $($_.Exception.Message)"
        throw
    }
}

# Function to create App Role
function New-AppRole {
    param(
        [string]$VaultUrl,
        [string]$Token,
        [string]$RoleName
    )
    
    Write-Host "🤖 Creating App Role: $RoleName" -ForegroundColor Cyan
    
    $headers = @{ "X-Vault-Token" = $Token }
    
    # Create App Role with TTL settings
    $roleConfig = @{
        token_policies = @("octopus-automation")
        token_ttl = "1h"
        token_max_ttl = "4h"
        bind_secret_id = $true
        secret_id_ttl = "24h"
        secret_id_num_uses = 10
        token_period = 0
    } | ConvertTo-Json
    
    try {
        Invoke-RestMethod -Uri "$VaultUrl/v1/auth/approle/role/$RoleName" -Method Post -Body $roleConfig -Headers $headers -ContentType "application/json"
        Write-Host "✅ App Role created successfully" -ForegroundColor Green
        
        # Get Role ID
        $roleIdResponse = Invoke-RestMethod -Uri "$VaultUrl/v1/auth/approle/role/$RoleName/role-id" -Method Get -Headers $headers
        $roleId = $roleIdResponse.data.role_id
        
        # Generate Secret ID
        $secretIdResponse = Invoke-RestMethod -Uri "$VaultUrl/v1/auth/approle/role/$RoleName/secret-id" -Method Post -Headers $headers
        $secretId = $secretIdResponse.data.secret_id
        
        Write-Host "📋 App Role Details:" -ForegroundColor Yellow
        Write-Host "   Role ID: $roleId"
        Write-Host "   Secret ID: $secretId"
        Write-Host "   Token TTL: 1 hour"
        Write-Host "   Secret ID TTL: 24 hours"
        Write-Host "   Max Uses: 10"
        
        return @{
            RoleId = $roleId
            SecretId = $secretId
        }
    } catch {
        Write-Error "❌ Failed to create App Role: $($_.Exception.Message)"
        throw
    }
}

# Function to rotate Secret ID
function Update-SecretId {
    param(
        [string]$VaultUrl,
        [string]$Token,
        [string]$RoleName
    )
    
    Write-Host "🔄 Rotating Secret ID for: $RoleName" -ForegroundColor Cyan
    
    $headers = @{ "X-Vault-Token" = $Token }
    
    try {
        # Generate new Secret ID
        $secretIdResponse = Invoke-RestMethod -Uri "$VaultUrl/v1/auth/approle/role/$RoleName/secret-id" -Method Post -Headers $headers
        $newSecretId = $secretIdResponse.data.secret_id
        $secretIdAccessor = $secretIdResponse.data.secret_id_accessor
        
        Write-Host "✅ New Secret ID generated" -ForegroundColor Green
        Write-Host "   Secret ID: $newSecretId"
        Write-Host "   Accessor: $secretIdAccessor"
        Write-Host "   TTL: 24 hours"
        Write-Host "   Max Uses: 10"
        
        return @{
            SecretId = $newSecretId
            Accessor = $secretIdAccessor
        }
    } catch {
        Write-Error "❌ Failed to rotate Secret ID: $($_.Exception.Message)"
        throw
    }
}

# Function to get App Role status
function Get-AppRoleStatus {
    param(
        [string]$VaultUrl,
        [string]$Token,
        [string]$RoleName
    )
    
    Write-Host "📊 Getting App Role Status: $RoleName" -ForegroundColor Cyan
    
    $headers = @{ "X-Vault-Token" = $Token }
    
    try {
        # Get role configuration
        $roleResponse = Invoke-RestMethod -Uri "$VaultUrl/v1/auth/approle/role/$RoleName" -Method Get -Headers $headers
        $roleData = $roleResponse.data
        
        # Get Role ID
        $roleIdResponse = Invoke-RestMethod -Uri "$VaultUrl/v1/auth/approle/role/$RoleName/role-id" -Method Get -Headers $headers
        $roleId = $roleIdResponse.data.role_id
        
        # List Secret ID accessors
        $secretIdListResponse = Invoke-RestMethod -Uri "$VaultUrl/v1/auth/approle/role/$RoleName/secret-id" -Method Get -Headers $headers
        $secretIdAccessors = $secretIdListResponse.data.keys
        
        Write-Host "📋 App Role Status:" -ForegroundColor Yellow
        Write-Host "   Role Name: $RoleName"
        Write-Host "   Role ID: $roleId"
        Write-Host "   Token TTL: $($roleData.token_ttl)"
        Write-Host "   Token Max TTL: $($roleData.token_max_ttl)"
        Write-Host "   Secret ID TTL: $($roleData.secret_id_ttl)"
        Write-Host "   Secret ID Max Uses: $($roleData.secret_id_num_uses)"
        Write-Host "   Active Secret IDs: $($secretIdAccessors.Count)"
        Write-Host "   Policies: $($roleData.token_policies -join ', ')"
        
        # Show Secret ID details
        if ($secretIdAccessors.Count -gt 0) {
            Write-Host ""
            Write-Host "🔑 Active Secret IDs:" -ForegroundColor Yellow
            foreach ($accessor in $secretIdAccessors) {
                try {
                    $secretInfo = Invoke-RestMethod -Uri "$VaultUrl/v1/auth/approle/role/$RoleName/secret-id/lookup" -Method Post -Body (@{secret_id_accessor=$accessor} | ConvertTo-Json) -Headers $headers -ContentType "application/json"
                    $creationTime = [DateTimeOffset]::FromUnixTimeSeconds($secretInfo.data.creation_time).ToString("yyyy-MM-dd HH:mm:ss")
                    $expirationTime = [DateTimeOffset]::FromUnixTimeSeconds($secretInfo.data.expiration_time).ToString("yyyy-MM-dd HH:mm:ss")
                    
                    Write-Host "   Accessor: $accessor"
                    Write-Host "     Created: $creationTime"
                    Write-Host "     Expires: $expirationTime" 
                    Write-Host "     Uses Remaining: $($secretInfo.data.secret_id_num_uses)"
                } catch {
                    Write-Host "   Accessor: $accessor (details unavailable)"
                }
            }
        }
        
        return @{
            RoleId = $roleId
            SecretIdCount = $secretIdAccessors.Count
            Configuration = $roleData
        }
    } catch {
        Write-Error "❌ Failed to get App Role status: $($_.Exception.Message)"
        throw
    }
}

# Function to test App Role authentication
function Test-AppRoleAuth {
    param(
        [string]$VaultUrl,
        [string]$RoleId,
        [string]$SecretId
    )
    
    Write-Host "🧪 Testing App Role Authentication..." -ForegroundColor Cyan
    
    $authBody = @{
        role_id = $RoleId
        secret_id = $SecretId
    } | ConvertTo-Json
    
    try {
        $response = Invoke-RestMethod -Uri "$VaultUrl/v1/auth/approle/login" -Method Post -Body $authBody -ContentType "application/json"
        $token = $response.auth.client_token
        $ttl = $response.auth.lease_duration
        $policies = $response.auth.policies -join ', '
        
        Write-Host "✅ Authentication successful" -ForegroundColor Green
        Write-Host "   Token TTL: $ttl seconds"
        Write-Host "   Policies: $policies"
        
        # Test secret access
        $headers = @{ "X-Vault-Token" = $token }
        try {
            $secretTest = Invoke-RestMethod -Uri "$VaultUrl/v1/secret/data/cloudflare" -Method Get -Headers $headers
            Write-Host "✅ Secret access test successful" -ForegroundColor Green
        } catch {
            Write-Warning "⚠️ Secret access test failed (normal if secrets don't exist)"
        }
        
        # Revoke test token
        Invoke-RestMethod -Uri "$VaultUrl/v1/auth/token/revoke-self" -Method Post -Headers $headers
        Write-Host "🔒 Test token revoked" -ForegroundColor Gray
        
        return $true
    } catch {
        Write-Error "❌ Authentication test failed: $($_.Exception.Message)"
        return $false
    }
}

# Function to update Octopus Deploy variables
function Update-OctopusVariable {
    param(
        [string]$OctopusUrl,
        [string]$ApiKey,
        [string]$SpaceId,
        [string]$ProjectName,
        [string]$VariableName,
        [string]$VariableValue
    )
    
    Write-Host "🐙 Updating Octopus Deploy variable: $VariableName" -ForegroundColor Cyan
    
    $headers = @{
        "X-Octopus-ApiKey" = $ApiKey
        "Content-Type" = "application/json"
    }
    
    try {
        # Get project ID
        $projectsResponse = Invoke-RestMethod -Uri "$OctopusUrl/api/$SpaceId/projects" -Method Get -Headers $headers
        $project = $projectsResponse.Items | Where-Object { $_.Name -eq $ProjectName }
        
        if (-not $project) {
            throw "Project '$ProjectName' not found"
        }
        
        # Get variable set
        $variableSetResponse = Invoke-RestMethod -Uri "$OctopusUrl/api/$SpaceId/projects/$($project.Id)/variables" -Method Get -Headers $headers
        
        # Find existing variable
        $existingVariable = $variableSetResponse.Variables | Where-Object { $_.Name -eq $VariableName }
        
        if ($existingVariable) {
            Write-Host "   📝 Updating existing variable"
            $existingVariable.Value = $VariableValue
        } else {
            Write-Host "   ➕ Creating new variable"
            $newVariable = @{
                Name = $VariableName
                Value = $VariableValue
                IsSensitive = ($VariableName -like "*Secret*")
                Scope = @{}
            }
            $variableSetResponse.Variables += $newVariable
        }
        
        # Update variable set
        $updateBody = $variableSetResponse | ConvertTo-Json -Depth 10
        Invoke-RestMethod -Uri "$OctopusUrl/api/$SpaceId/variables/$($variableSetResponse.Id)" -Method Put -Body $updateBody -Headers $headers
        
        Write-Host "✅ Variable updated successfully" -ForegroundColor Green
        
    } catch {
        Write-Error "❌ Failed to update Octopus variable: $($_.Exception.Message)"
        throw
    }
}

# Function to cleanup old Secret IDs
function Remove-OldSecretIds {
    param(
        [string]$VaultUrl,
        [string]$Token,
        [string]$RoleName,
        [int]$KeepCount = 2
    )
    
    Write-Host "🧹 Cleaning up old Secret IDs..." -ForegroundColor Cyan
    
    $headers = @{ "X-Vault-Token" = $Token }
    
    try {
        # List Secret ID accessors
        $secretIdListResponse = Invoke-RestMethod -Uri "$VaultUrl/v1/auth/approle/role/$RoleName/secret-id" -Method Get -Headers $headers
        $secretIdAccessors = $secretIdListResponse.data.keys
        
        if ($secretIdAccessors.Count -le $KeepCount) {
            Write-Host "   No cleanup needed (only $($secretIdAccessors.Count) Secret IDs)" -ForegroundColor Green
            return
        }
        
        # Get creation times and sort
        $secretDetails = @()
        foreach ($accessor in $secretIdAccessors) {
            try {
                $secretInfo = Invoke-RestMethod -Uri "$VaultUrl/v1/auth/approle/role/$RoleName/secret-id/lookup" -Method Post -Body (@{secret_id_accessor=$accessor} | ConvertTo-Json) -Headers $headers -ContentType "application/json"
                $secretDetails += @{
                    Accessor = $accessor
                    CreationTime = $secretInfo.data.creation_time
                }
            } catch {
                # Skip if can't get details
            }
        }
        
        # Sort by creation time and remove oldest
        $sortedSecrets = $secretDetails | Sort-Object CreationTime -Descending
        $toRemove = $sortedSecrets | Select-Object -Skip $KeepCount
        
        foreach ($secret in $toRemove) {
            try {
                $destroyBody = @{ secret_id_accessor = $secret.Accessor } | ConvertTo-Json
                Invoke-RestMethod -Uri "$VaultUrl/v1/auth/approle/role/$RoleName/secret-id/destroy" -Method Post -Body $destroyBody -Headers $headers -ContentType "application/json"
                Write-Host "   🗑️ Removed Secret ID: $($secret.Accessor)" -ForegroundColor Gray
            } catch {
                Write-Warning "   ⚠️ Failed to remove Secret ID: $($secret.Accessor)"
            }
        }
        
        Write-Host "✅ Cleanup completed" -ForegroundColor Green
        
    } catch {
        Write-Error "❌ Failed to cleanup Secret IDs: $($_.Exception.Message)"
    }
}

# Main execution
Write-Host "🤖 App Role Management for Octopus Deploy" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green

# Get Vault token for administration
$vaultToken = $env:VAULT_TOKEN
if (-not $vaultToken) {
    $vaultToken = Get-VaultTokenInteractive -VaultUrl $VaultUrl
}

switch ($Action) {
    "Create" {
        $result = New-AppRole -VaultUrl $VaultUrl -Token $vaultToken -RoleName $RoleName
        
        if ($OctopusApiKey) {
            Write-Host ""
            Write-Host "🐙 Updating Octopus Deploy variables..." -ForegroundColor Yellow
            Update-OctopusVariable -OctopusUrl $OctopusUrl -ApiKey $OctopusApiKey -SpaceId $OctopusSpaceId -ProjectName $OctopusProjectName -VariableName "Vault.AppRoleId" -VariableValue $result.RoleId
            Update-OctopusVariable -OctopusUrl $OctopusUrl -ApiKey $OctopusApiKey -SpaceId $OctopusSpaceId -ProjectName $OctopusProjectName -VariableName "Vault.AppSecretId" -VariableValue $result.SecretId
        }
    }
    
    "Rotate" {
        $result = Update-SecretId -VaultUrl $VaultUrl -Token $vaultToken -RoleName $RoleName
        
        if ($OctopusApiKey) {
            Write-Host ""
            Write-Host "🐙 Updating Octopus Deploy Secret ID..." -ForegroundColor Yellow
            Update-OctopusVariable -OctopusUrl $OctopusUrl -ApiKey $OctopusApiKey -SpaceId $OctopusSpaceId -ProjectName $OctopusProjectName -VariableName "Vault.AppSecretId" -VariableValue $result.SecretId
        }
        
        # Cleanup old Secret IDs
        Remove-OldSecretIds -VaultUrl $VaultUrl -Token $vaultToken -RoleName $RoleName
    }
    
    "Status" {
        Get-AppRoleStatus -VaultUrl $VaultUrl -Token $vaultToken -RoleName $RoleName
    }
    
    "Test" {
        $status = Get-AppRoleStatus -VaultUrl $VaultUrl -Token $vaultToken -RoleName $RoleName
        # This would need Role ID and Secret ID from Octopus variables to test
        Write-Host "💡 To test authentication, provide Role ID and Secret ID" -ForegroundColor Yellow
    }
    
    "Cleanup" {
        Remove-OldSecretIds -VaultUrl $VaultUrl -Token $vaultToken -RoleName $RoleName
    }
}

Write-Host ""
Write-Host "✨ App Role management completed!" -ForegroundColor Green
