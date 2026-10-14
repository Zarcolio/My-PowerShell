<#
.SYNOPSIS
Find-PlaintextSecrets.ps1

.DESCRIPTION
Defensive auditing tool that scans targeted locations for likely plaintext
credentials or secrets. It extracts candidate secret values, evaluates them
for plausibility (length, entropy, defaults), detects encrypted blobs
(e.g., Base64 that decodes to mostly non-printable bytes such as DPAPI /
SecureString artifacts), and filters out common non-secret trailing tokens.

This script DOES NOT:
 - Dump credentials
 - Access LSASS/SAM/DPAPI
 - Decrypt secrets
 - Escalate privileges

It only searches files and reports possible plaintext secrets.

.PARAMETERS
-Paths          Optional custom scan roots
-Recurse        Scan subdirectories (default true)
-MaxFileSizeMB  Skip files larger than this size (default 5)
-ContextChars   Snippet length (default 120)
-OutFile        Optional report output
-Quiet          Suppress finding output
#>

[CmdletBinding()]
param(
    [string[]]$Paths,
    [bool]$Recurse = $true,
    [int]$MaxFileSizeMB = 5,
    [int]$ContextChars = 120,
    [string]$OutFile,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --------------------------------------------------
# Allowed extensions
# --------------------------------------------------

$AllowedExtensions = @(
'.txt','.log','.config','.ini','.json','.xml','.env',
'.ps1','.psm1','.bat','.cmd','.yml','.yaml','.properties',
'.sql','.cfg','.conf','.tf','.tfvars'
)

# --------------------------------------------------
# Suspicious filenames
# --------------------------------------------------

$SuspiciousFilenames = @(
'passwords.txt','credentials.txt','secrets.txt','accounts.txt',
'backup.ps1','deploy.ps1','db.config',
'.env','.env.local','.env.production',
'admin-settings.json','daemon.json','NuGet.Config'
)

# --------------------------------------------------
# Words that are commonly captured but are NOT secrets
# --------------------------------------------------

$NonSecretTokens = @(
'&quot;','&amp;','&lt;','&gt;',
'token','tokens','tokenization',
'string','strings',
'value','values',
'example','examples',
'sample','samples',
'dummy','placeholder','default',
'config','configuration',
'null','none','empty',
'true','false',
'json','xml','html',
'param','params','parameter',
'data','metadata',
'user','username','userid',
'password','pwd',
'key','keys',
'secret','secrets',
'test','testing',
'input','output'
)

# --------------------------------------------------
# Default scan roots
# --------------------------------------------------

$DefaultScanRoots = @(
"$env:USERPROFILE\Desktop",
"$env:USERPROFILE\Documents",
"$env:USERPROFILE\Downloads",
"$env:USERPROFILE\Scripts",
"$env:USERPROFILE\source",
"$env:USERPROFILE\projects",
"$env:USERPROFILE\.ssh",
"$env:APPDATA",
"$env:LOCALAPPDATA",
"$env:USERPROFILE\.config",
"$env:USERPROFILE\.aws",
"$env:USERPROFILE\.azure",

"$env:ProgramData\Microsoft\IntuneManagementExtension",
"$env:ProgramData\DockerDesktop",
"$env:ProgramData\docker\config",

"C:\Windows\Panther",
"C:\Windows\System32\Sysprep",

"${env:ProgramFiles(x86)}\Microsoft Intune Management Extension",
"${env:ProgramFiles(x86)}\NuGet\Config"
)

# --------------------------------------------------
# Regex patterns with capture group "secret"
# --------------------------------------------------

$Patterns = @(
@{Name='PasswordAssignment';Regex='(?i)\b(password|passwd|pwd|db_password|smtp_password)\s*[:=]\s*(?<secret>[^\s;,"'']+)';Risk='High'}
@{Name='SecretAssignment';Regex='(?i)\b(secret|client_secret|private_key)\s*[:=]\s*(?<secret>[^\s;,"'']+)';Risk='High'}
@{Name='APIKey';Regex='(?i)\b(token|apikey|api_key|access_key)\s*[:=]\s*(?<secret>[A-Za-z0-9\-_\.=]{6,})';Risk='Medium'}
@{Name='BearerToken';Regex='(?i)Authorization\s*:\s*Bearer\s+(?<secret>[A-Za-z0-9\-_\.=]{10,})';Risk='Medium'}
@{Name='URLCredential';Regex='(?i)[a-z]+:\/\/[^\/\s:@]+:(?<secret>[^@\s]+)@';Risk='High'}
@{Name='ConnectionString';Regex='(?i)Password\s*=\s*(?<secret>[^;]+)';Risk='High'}
@{Name='PSPasswordVar';Regex='(?i)\$password\s*=\s*["'']?(?<secret>[^"'']+)';Risk='High'}
@{Name='PrivateKey';Regex='(?i)BEGIN\s+(RSA\s+)?PRIVATE\s+KEY';Risk='High'}
)

# --------------------------------------------------
# Program Files allowlist
# --------------------------------------------------

$ProgramFilesAllow = @(
"${env:ProgramFiles(x86)}\Microsoft Intune Management Extension",
"${env:ProgramFiles(x86)}\NuGet\Config"
)

# --------------------------------------------------
# Utility: Shannon entropy
# --------------------------------------------------

function Get-Entropy {
param([string]$s)

if([string]::IsNullOrEmpty($s)){ return 0 }

$freq=@{}
foreach($c in $s.ToCharArray()){
    if(!$freq.ContainsKey($c)){ $freq[$c]=0 }
    $freq[$c]++
}

$entropy=0
foreach($count in $freq.Values){
    $p=$count/$s.Length
    $entropy += -$p * [Math]::Log($p,2)
}

return $entropy
}

# --------------------------------------------------
# Detect Base64 encrypted blobs (DPAPI etc.)
# --------------------------------------------------

function Test-EncryptedBlob {
param([string]$value)

if([string]::IsNullOrWhiteSpace($value)){ return $false }

if($value.Length -lt 16){ return $false }

if($value -notmatch '^[A-Za-z0-9+/=]+$'){ return $false }

try{
    $bytes=[Convert]::FromBase64String($value)
}catch{
    return $false
}

if($bytes.Length -lt 8){ return $false }

$printable = @($bytes | Where-Object {$_ -ge 32 -and $_ -le 126}).Count
$ratio = $printable / $bytes.Length

if($ratio -lt 0.3){
    return $true
}

return $false
}

# --------------------------------------------------
# Evaluate secret plausibility
# --------------------------------------------------

function Evaluate-Secret {
param([string]$secret)

if([string]::IsNullOrWhiteSpace($secret)){
    return @{Valid=$false;Entropy=0;Encrypted=$false}
}

$secret=$secret.Trim()

if($NonSecretTokens -contains $secret.ToLower()){
    return @{Valid=$false;Entropy=0;Encrypted=$false}
}

if(Test-EncryptedBlob $secret){
    return @{Valid=$true;Entropy=0;Encrypted=$true}
}

if($secret.Length -lt 4){
    return @{Valid=$false;Entropy=0;Encrypted=$false}
}

if($secret -match '^(password|changeme|example|test|dummy|null)$'){
    return @{Valid=$false;Entropy=0;Encrypted=$false}
}

$entropy = Get-Entropy $secret

if($entropy -lt 2){
    return @{Valid=$false;Entropy=$entropy;Encrypted=$false}
}

return @{Valid=$true;Entropy=$entropy;Encrypted=$false}
}

# --------------------------------------------------
# Path exclusion
# --------------------------------------------------

function Is-AllowlistedProgramFilesPath {
param($Path)

$p=[IO.Path]::GetFullPath($Path)

foreach($allowed in $ProgramFilesAllow){
    if(!$allowed){continue}
    $a=[IO.Path]::GetFullPath($allowed)
    if($p.StartsWith($a,[System.StringComparison]::OrdinalIgnoreCase)){return $true}
}

return $false
}

function Is-ExcludedPath {
param($Path)

$p=[IO.Path]::GetFullPath($Path)

if($env:ProgramFiles){
    if($p.StartsWith($env:ProgramFiles,[System.StringComparison]::OrdinalIgnoreCase)){
        if(!(Is-AllowlistedProgramFilesPath $p)){return $true}
    }
}

if(${env:ProgramFiles(x86)}){
    if($p.StartsWith(${env:ProgramFiles(x86)},[System.StringComparison]::OrdinalIgnoreCase)){
        if(!(Is-AllowlistedProgramFilesPath $p)){return $true}
    }
}

if($p.StartsWith("C:\Windows",[System.StringComparison]::OrdinalIgnoreCase)){
    if(!$p.StartsWith("C:\Windows\Panther",[System.StringComparison]::OrdinalIgnoreCase) -and
       !$p.StartsWith("C:\Windows\System32\Sysprep",[System.StringComparison]::OrdinalIgnoreCase)){
        return $true
    }
}

if($p -match '\\node_modules\\'){return $true}
if($p -match '\\\.git\\objects\\'){return $true}

return $false
}

# --------------------------------------------------
# State
# --------------------------------------------------

$Findings=@()
$Skipped=@()
$FilesScanned=0
$MaxBytes=$MaxFileSizeMB*1MB

# --------------------------------------------------
# File scanning
# --------------------------------------------------

function Scan-File {
param($File)

$script:FilesScanned++

try{

$reader=[System.IO.StreamReader]::new($File)
$line=0

while(!$reader.EndOfStream){

$content=$reader.ReadLine()
$line++

foreach($rule in $Patterns){

$matches=[regex]::Matches($content,$rule.Regex)

foreach($m in @($matches)){

$secret=""
if($m.Groups['secret']){ $secret=$m.Groups['secret'].Value }

$evaluation=Evaluate-Secret $secret

if(!$evaluation.Valid -and $secret){
    continue
}

$snippet=$content
if($snippet.Length -gt $ContextChars){
    $snippet=$snippet.Substring(0,$ContextChars)
}

$risk=$rule.Risk
$name=[IO.Path]::GetFileName($File)

if($evaluation.Encrypted){
    $risk="Low"
}

if($SuspiciousFilenames -contains $name){
    if($risk -eq "Low"){$risk="Medium"}
    elseif($risk -eq "Medium"){$risk="High"}
}

$obj=[PSCustomObject]@{
Risk=$risk
Path=$File
Line=$line
Rule=$rule.Name
Secret=$secret
Entropy=$evaluation.Entropy
Encrypted=$evaluation.Encrypted
Snippet=$snippet
}

$Findings+=$obj

if(!$Quiet){

$displaySecret=$secret
if($displaySecret.Length -gt 40){
$displaySecret=$displaySecret.Substring(0,40)+"..."
}

$type="Plain"
if($evaluation.Encrypted){$type="EncryptedBlob"}

Write-Output ("H={0:N2} | [{1}] {2}:{3} | {4} | {5} | Secret='{6}'" -f `
$evaluation.Entropy,$risk,$File,$line,$rule.Name,$type,$displaySecret)

}

}

}

}

$reader.Close()

}catch{

$Skipped+="$File (read error)"

}

}

# --------------------------------------------------
# Directory traversal
# --------------------------------------------------

function Get-TargetFilesFromRoot {
param($Root)

if(!(Test-Path $Root)){return}

$stack=[System.Collections.Stack]::new()
$stack.Push($Root)

while($stack.Count -gt 0){

$dir=$stack.Pop()

try{
$files=@(Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction Stop)
}catch{
$Skipped+="$dir (file enumeration error)"
continue
}

foreach($f in $files){

if(Is-ExcludedPath $f.FullName){continue}

if($f.Length -gt $MaxBytes){
$Skipped+="$($f.FullName) (too large)"
continue
}

if($AllowedExtensions -contains $f.Extension.ToLower()){
Scan-File $f.FullName
}

}

if($Recurse){

try{
$dirs=@(Get-ChildItem -LiteralPath $dir -Directory -Force -ErrorAction Stop)
}catch{
$Skipped+="$dir (dir enumeration error)"
continue
}

foreach($d in @($dirs)){
if(!(Is-ExcludedPath $d.FullName)){
$stack.Push($d.FullName)
}
}

}

}

}

# --------------------------------------------------
# Start scan
# --------------------------------------------------

$Roots = if($Paths){$Paths}else{$DefaultScanRoots}

foreach($r in @($Roots)){
Get-TargetFilesFromRoot $r
}

# --------------------------------------------------
# Summary
# --------------------------------------------------

$HighRisk = @($Findings | Where-Object {$_.Risk -eq "High"}).Count

Write-Output ""
Write-Output "===== SUMMARY ====="
Write-Output "Files scanned : $FilesScanned"
Write-Output "Findings      : $(@($Findings).Count)"
Write-Output "High risk     : $HighRisk"
Write-Output "Skipped items : $(@($Skipped).Count)"

# --------------------------------------------------
# Optional report
# --------------------------------------------------

if($OutFile){

$report=@()

foreach($f in @($Findings)){
$type="Plain"
if($f.Encrypted){$type="EncryptedBlob"}

$report+=("H={0:N2} | [{1}] {2}:{3} | {4} | {5} | Secret='{6}'" -f `
$f.Entropy,$f.Risk,$f.Path,$f.Line,$f.Rule,$type,$f.Secret)
}

$report+=""
$report+="===== SUMMARY ====="
$report+="Files scanned : $FilesScanned"
$report+="Findings      : $(@($Findings).Count)"
$report+="High risk     : $HighRisk"
$report+="Skipped items : $(@($Skipped).Count)"

$report | Out-File -Encoding utf8 $OutFile
}