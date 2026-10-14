<#
.SYNOPSIS
    Credential scanner with contextual truncation, Base64 recursion,
    path exclusions, translated password keywords, and self-output exclusion.

.COMPATIBILITY
    - Compatible with Windows PowerShell 5.1+
    - No null-conditional operators (?.)
#>

[CmdletBinding()]
param (
    [bool]$IncludeLocalDrives       = $true,
    [bool]$IncludeRemovableDrives   = $false,
    [bool]$IncludeNetworkDrives     = $false,

    [bool]$UseDefaultExtensions     = $true,
    [string[]]$AdditionalExtensions = @(),
    [string[]]$OnlyExtensions       = @(),

    [string]$ExcludePathsCSL        = "",

    [bool]$IncludeHashIndicators    = $false,

    [string]$PasswordKeywordsCSL    = "",

    [ValidateSet("Screen", "File", "ScreenAndFile")]
    [string]$OutputMode = "Screen",

    [string]$OutputFilePath = ".\credential-string-scan-results.txt"
)

begin {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"

    # -------------------------------
    # Resolve output file early (for self-exclusion)
    # -------------------------------
    $ResolvedOutputFile = $null
    if ($OutputMode -in @("File","ScreenAndFile")) {
        New-Item -ItemType File -Path $OutputFilePath -Force | Out-Null
        $ResolvedOutputFile = (Resolve-Path -Path $OutputFilePath).Path
    }

    # -------------------------------
    # File extensions
    # -------------------------------
    $DefaultExtensions = @(
        "txt","log","cfg","conf","ini","inf","env",
        "json","yaml","yml","xml","csv","tsv",
        "ps1","psm1","psd1","bat","cmd","vbs","wsf","wsh","hta",
        "sql","reg","pol","eml",
        "bak","backup","old","tmp","eml",
        "properties","prefs","cnf",
        "cred","secrets","vault",
        "netrc","npmrc","pypirc","dockercfg",
        "tfstate","tfvars","pipeline","helm","kubeconfig"
    )

    # -------------------------------
    # Password keywords (base + translations)
    # -------------------------------
    $PasswordKeywords = @("pass","password","pwd")
    if ($PasswordKeywordsCSL) {
        $PasswordKeywords += $PasswordKeywordsCSL.Split(",") |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ }
    }

    $PasswordKeywordRegex = ($PasswordKeywords |
        Sort-Object -Unique |
        ForEach-Object { [regex]::Escape($_) }) -join "|"

    # -------------------------------
    # Credential patterns (hashes optional)
    # -------------------------------
    $CredentialPatterns = @(
        @{ Type="PasswordAssignment"; Regex="(?i)\b($PasswordKeywordRegex)\b\s*[:=]\s*[""']?.{4,}[""']?" },
        @{ Type="GenericSecret"; Regex='(?i)\b(secret|seckey|private[_\- ]?key)\b\s*[:=]\s*.+?' },
        @{ Type="APIKey"; Regex='(?i)\b(api[_\- ]?key|api[_\- ]?secret)\b\s*[:=]\s*.+?' },
        @{ Type="AuthToken"; Regex='(?i)\b(token|auth[_\- ]?token|bearer)\b\s*[:=]\s*.+?' },
        @{ Type="AWSAccessKey"; Regex='AKIA[0-9A-Z]{16}' },
        @{ Type="AWSTempKey"; Regex='ASIA[0-9A-Z]{16}' },
        @{ Type="AWSSecretKey"; Regex='(?i)aws(.{0,20})?(secret|access)[_\- ]?key\s*[:=]\s*[A-Za-z0-9/+=]{30,}' },
        @{ Type="GoogleAPIKey"; Regex='AIza[0-9A-Za-z\-_]{35}' },
        @{ Type="GoogleOAuth"; Regex='ya29\.[0-9A-Za-z\-_]+' },
        @{ Type="AzureSecret"; Regex='(?i)\b(client|tenant|subscription)[_\- ]?secret\b\s*[:=]\s*.+?' },
        @{ Type="DBConnection"; Regex='(?i)(server|host|data source)=.+;(user id|uid|username)=.+;(password|pwd)=.+' },

        # NEW: URL-embedded credentials (protocol://user:password@host)
        @{ Type="URLCredentials"; Regex='(?i)\b[a-z][a-z0-9+\-.]*://[^:\s/@]+:[^@\s]+@' },

        @{ Type="URIWithCreds"; Regex='(?i)(mongodb|mysql|postgres|mssql|oracle)://[^@\s]+:[^@\s]+@' },
        @{ Type="PrivateKey"; Regex='-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----' },
        @{ Type="PSSecureStringPlaintext"; Regex='(?i)ConvertTo-SecureString\s+["''][^"'']+["''](\s+-AsPlainText)?(\s+-Force)?' }
    )

    if ($IncludeHashIndicators) {
        $CredentialPatterns += @(
            @{ Type="Hash_MD5"; Regex='\b[a-f0-9]{32}\b' },
            @{ Type="Hash_SHA1"; Regex='\b[a-f0-9]{40}\b' },
            @{ Type="Hash_SHA256"; Regex='\b[a-f0-9]{64}\b' }
        )
    }

    # -------------------------------
    # Base64 detection
    # -------------------------------
    $Base64Regex = '(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}'

    # -------------------------------
    # Excluded paths
    # -------------------------------
    $ExcludedPaths = @()
    if ($ExcludePathsCSL) {
        $ExcludedPaths = $ExcludePathsCSL.Split(",") |
            ForEach-Object { $_.Trim().TrimEnd("\") + "\" }
    }

    # -------------------------------
    # Helper: emit result with truncation
    # -------------------------------
    function Emit-Result {
        param (
            [string]$Source,
            [string]$Type,
            [string]$Value
        )

        if ($Value.Length -le 200) {
            $line = "$Source | $Type | $Value"
            if ($OutputMode -in @("Screen","ScreenAndFile")) { Write-Output $line }
            if ($OutputMode -in @("File","ScreenAndFile")) { Add-Content $OutputFilePath $line }
            return
        }

        foreach ($Pattern in $CredentialPatterns) {
            foreach ($Sub in [regex]::Matches($Value, $Pattern.Regex)) {
                $start = [Math]::Max(0, $Sub.Index - 50)
                $end   = [Math]::Min($Value.Length, $Sub.Index + $Sub.Length + 100)
                $slice = $Value.Substring($start, $end - $start)

                $line = "$Source | $($Pattern.Type) | $slice"
                if ($OutputMode -in @("Screen","ScreenAndFile")) { Write-Output $line }
                if ($OutputMode -in @("File","ScreenAndFile")) { Add-Content $OutputFilePath $line }
            }
        }
    }

    # -------------------------------
    # Helper: scan text (recursive Base64)
    # -------------------------------
    function Scan-TextBlock {
        param (
            [string]$Text,
            [string]$Source,
            [int]$Depth = 0
        )

        if ($Depth -gt 2) { return }

        foreach ($Pattern in $CredentialPatterns) {
            foreach ($Match in [regex]::Matches($Text, $Pattern.Regex)) {
                Emit-Result -Source $Source -Type $Pattern.Type -Value $Match.Value
            }
        }

        foreach ($B64 in [regex]::Matches($Text, $Base64Regex)) {
            try {
                $decoded = [Text.Encoding]::UTF8.GetString(
                    [Convert]::FromBase64String($B64.Value)
                )
                if ($decoded -match '[\x09\x0A\x0D\x20-\x7E]{10,}') {
                    Scan-TextBlock -Text $decoded -Source "$Source | base64(decoded)" -Depth ($Depth + 1)
                }
            } catch { }
        }
    }
}

process {
    $DriveRoots = Get-PSDrive -PSProvider FileSystem |
        Where-Object {
            ($IncludeLocalDrives -and $_.DisplayRoot -eq $null) -or
            ($IncludeRemovableDrives -and $_.Description -match "Removable") -or
            ($IncludeNetworkDrives -and $_.DisplayRoot)
        } |
        Select-Object -ExpandProperty Root |
        Sort-Object -Unique

    foreach ($Root in $DriveRoots) {
        Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                if ($ResolvedOutputFile -and $_.FullName -eq $ResolvedOutputFile) { return $false }
                foreach ($Ex in $ExcludedPaths) {
                    if ($_.FullName.StartsWith($Ex, [StringComparison]::OrdinalIgnoreCase)) {
                        return $false
                    }
                }
                $DefaultExtensions -contains $_.Extension.TrimStart(".").ToLowerInvariant()
            } |
            ForEach-Object {
                try {
                    Scan-TextBlock -Text (Get-Content $_.FullName -Raw) -Source $_.FullName
                } catch { }
            }
    }
}

end {
    Write-Verbose "Credential scan completed successfully."
}
