Write-Host "=== Windows Hello for Business / Microsoft Entra ID Check ===" -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------------------------
# 1. Read dsregcmd output
# ------------------------------------------------------------
$dsregOutput = dsregcmd /status

function Get-DsregValue {
    param(
        [string]$Name
    )

    $line = $dsregOutput |
        Where-Object { $_ -match "^\s*$([regex]::Escape($Name))\s*:" } |
        Select-Object -First 1

    if ($line) {
        return ($line -split ":", 2)[1].Trim()
    }

    return "NOT FOUND"
}

$azureAdJoined   = Get-DsregValue "AzureAdJoined"
$domainJoined    = Get-DsregValue "DomainJoined"
$tpmProtected    = Get-DsregValue "TpmProtected"
$deviceAuth      = Get-DsregValue "DeviceAuthStatus"
$ngcSet          = Get-DsregValue "NgcSet"
$azureAdPrt      = Get-DsregValue "AzureAdPrt"
$workplaceJoined = Get-DsregValue "WorkplaceJoined"
$mdmUrl          = Get-DsregValue "MdmUrl"
$tenantName      = Get-DsregValue "TenantName"
$tenantId        = Get-DsregValue "TenantId"

# ------------------------------------------------------------
# 2. Check Windows Hello for Business policy
# ------------------------------------------------------------
$passportRootPath = "HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork"
$usePassportForWork = $null
$passportPolicyPath = $null

if (Test-Path $passportRootPath) {

    $passportPolicy = Get-ChildItem $passportRootPath -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
            try {
                $item = Get-ItemProperty $_.PSPath -ErrorAction Stop

                if ($item.PSObject.Properties.Name -contains "UsePassportForWork") {
                    [PSCustomObject]@{
                        Path               = $_.Name
                        UsePassportForWork = $item.UsePassportForWork
                    }
                }
            }
            catch {
                # Ignore inaccessible registry keys
            }
        } |
        Select-Object -First 1

    if ($passportPolicy) {
        $usePassportForWork = $passportPolicy.UsePassportForWork
        $passportPolicyPath = $passportPolicy.Path
    }
}

# ------------------------------------------------------------
# 3. Display collected information
# ------------------------------------------------------------
Write-Host "Tenant" -ForegroundColor Yellow
Write-Host "Tenant name               : $tenantName"
Write-Host "Tenant ID                 : $tenantId"
Write-Host ""

Write-Host "Device status" -ForegroundColor Yellow
Write-Host "Microsoft Entra joined    : $azureAdJoined"
Write-Host "Domain joined             : $domainJoined"
Write-Host "Workplace joined          : $workplaceJoined"
Write-Host "Device authentication     : $deviceAuth"
Write-Host "TPM protected             : $tpmProtected"
Write-Host ""

Write-Host "User / SSO status" -ForegroundColor Yellow
Write-Host "Windows Hello credential  : $ngcSet"
Write-Host "Microsoft Entra PRT       : $azureAdPrt"
Write-Host ""

Write-Host "Management" -ForegroundColor Yellow
Write-Host "MDM URL present           : $(if ($mdmUrl -and $mdmUrl -ne 'NOT FOUND') { 'YES' } else { 'NO' })"
Write-Host ""

Write-Host "Windows Hello for Business policy" -ForegroundColor Yellow

if ($usePassportForWork -eq 1) {
    Write-Host "WHfB policy enabled       : YES" -ForegroundColor Green
    Write-Host "Policy path               : $passportPolicyPath"
}
elseif ($usePassportForWork -eq 0) {
    Write-Host "WHfB policy enabled       : NO" -ForegroundColor Red
    Write-Host "Policy path               : $passportPolicyPath"
}
else {
    Write-Host "WHfB policy enabled       : NOT EXPLICITLY FOUND" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Assessment ===" -ForegroundColor Cyan

# ------------------------------------------------------------
# 4. Build assessment results
# ------------------------------------------------------------
$checks = @()

$checks += [PSCustomObject]@{
    Check  = "Microsoft Entra joined"
    Result = if ($azureAdJoined -eq "YES") { "PASS" } else { "FAIL" }
}

$checks += [PSCustomObject]@{
    Check  = "Cloud-only / not domain joined"
    Result = if ($domainJoined -eq "NO") { "PASS" } else { "INFO" }
}

$checks += [PSCustomObject]@{
    Check  = "Device authentication"
    Result = if ($deviceAuth -eq "SUCCESS") { "PASS" } else { "FAIL" }
}

$checks += [PSCustomObject]@{
    Check  = "TPM protection"
    Result = if ($tpmProtected -eq "YES") { "PASS" } else { "WARN" }
}

$checks += [PSCustomObject]@{
    Check  = "Windows Hello configured"
    Result = if ($ngcSet -eq "YES") { "PASS" } else { "FAIL" }
}

$checks += [PSCustomObject]@{
    Check  = "Microsoft Entra Primary Refresh Token"
    Result = if ($azureAdPrt -eq "YES") { "PASS" } else { "WARN" }
}

$checks += [PSCustomObject]@{
    Check  = "Windows Hello for Business policy"
    Result = if ($usePassportForWork -eq 1) {
        "PASS"
    }
    elseif ($usePassportForWork -eq 0) {
        "FAIL"
    }
    else {
        "WARN"
    }
}

$checks | Format-Table -AutoSize

# ------------------------------------------------------------
# 5. Final conclusion
# ------------------------------------------------------------
$whfbConfirmed =
    ($azureAdJoined -eq "YES") -and
    ($ngcSet -eq "YES") -and
    ($tpmProtected -eq "YES") -and
    ($usePassportForWork -eq 1)

Write-Host ""

if ($whfbConfirmed) {
    Write-Host "RESULT: Windows Hello for Business is active and TPM protected." -ForegroundColor Green
}
else {
    Write-Host "RESULT: Windows Hello for Business could not be fully confirmed." -ForegroundColor Yellow
    Write-Host "Review the FAIL and WARN results above."
}