<# 
.SYNOPSIS
  Sanitizes CURRENT clipboard content to clean plain text (Ctrl+V will paste text-only).

.BEHAVIOR
  - Inspects Win32 clipboard formats (Text/UnicodeText/HTML Format/Rich Text Format).
  - Extracts best available textual representation (prefers UnicodeText).
  - Normalizes whitespace/line-endings and trims.
  - Writes back *only* plain Unicode text.
  - Silent on success.
  - On error: descriptive message + pause, non-zero exit code.

.COMPATIBILITY
  - Windows PowerShell 5.1: OK.
  - PowerShell 7+: OK on Windows (requires System.Windows.Forms).
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail-AndPause {
  param(
    [Parameter(Mandatory)][string]$Message,
    [Parameter(Mandatory)][int]$ExitCode
  )
  Write-Host ""
  Write-Host "ERROR: $Message" -ForegroundColor Red
  Write-Host ""
  Write-Host "Press any key to exit..."
  [void][System.Console]::ReadKey($true)
  exit $ExitCode
}

function Ensure-WinForms {
  try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop | Out-Null
  } catch {
    Fail-AndPause -Message "System.Windows.Forms could not be loaded. Windows clipboard APIs required." -ExitCode 10
  }
}

function Get-ClipboardDataObject {
  Ensure-WinForms
  try {
    return [System.Windows.Forms.Clipboard]::GetDataObject()
  } catch {
    Fail-AndPause -Message "Clipboard is unavailable or locked by another process." -ExitCode 11
  }
}

function Get-AvailableFormats {
  param([Parameter(Mandatory)] $DataObject)
  try {
    return @($DataObject.GetFormats($true))
  } catch {
    Fail-AndPause -Message "Failed to enumerate clipboard formats." -ExitCode 12
  }
}

function Convert-RtfToText {
  param([Parameter(Mandatory)][string] $Rtf)

  Ensure-WinForms
  $rtb = New-Object System.Windows.Forms.RichTextBox
  try {
    $rtb.Rtf = $Rtf
    return $rtb.Text
  } catch {
    Fail-AndPause -Message "Failed to convert RTF content to plain text." -ExitCode 20
  } finally {
    $rtb.Dispose()
  }
}

function Convert-HtmlFormatToText {
  param([Parameter(Mandatory)][string] $HtmlFormat)

  $html = $null
  $len  = $HtmlFormat.Length

  $mStartFrag = [regex]::Match($HtmlFormat, 'StartFragment:(\d+)', 'IgnoreCase')
  $mEndFrag   = [regex]::Match($HtmlFormat, 'EndFragment:(\d+)',   'IgnoreCase')
  $mStartHtml = [regex]::Match($HtmlFormat, 'StartHTML:(\d+)',     'IgnoreCase')
  $mEndHtml   = [regex]::Match($HtmlFormat, 'EndHTML:(\d+)',       'IgnoreCase')

  if ($mStartFrag.Success -and $mEndFrag.Success) {
    $s = [int]$mStartFrag.Groups[1].Value
    $e = [int]$mEndFrag.Groups[1].Value
    if ($s -ge 0 -and $e -gt $s -and $e -le $len) {
      $html = $HtmlFormat.Substring($s, $e - $s)
    }
  }

  if (-not $html -and $mStartHtml.Success -and $mEndHtml.Success) {
    $s = [int]$mStartHtml.Groups[1].Value
    $e = [int]$mEndHtml.Groups[1].Value
    if ($s -ge 0 -and $e -gt $s -and $e -le $len) {
      $html = $HtmlFormat.Substring($s, $e - $s)
    }
  }

  if (-not $html) {
    $html = $HtmlFormat
  }

  # Minimal HTML -> text conversion
  $t = $html
  $t = $t -replace '(?is)<\s*br\s*/?\s*>', "`n"
  $t = $t -replace '(?is)</\s*p\s*>', "`n`n"
  $t = $t -replace '(?is)</\s*div\s*>', "`n"
  $t = $t -replace '(?is)</\s*li\s*>', "`n"
  $t = $t -replace '(?is)<\s*li\b[^>]*>', " - "
  $t = $t -replace '(?is)<\s*script\b[^>]*>.*?</\s*script\s*>', ''
  $t = $t -replace '(?is)<\s*style\b[^>]*>.*?</\s*style\s*>', ''
  $t = [regex]::Replace($t, '(?is)<[^>]+>', '')

  $t = [System.Net.WebUtility]::HtmlDecode($t)
  return $t
}

function Get-TextFromDataObject {
  param(
    [Parameter(Mandatory)] $DataObject,
    [Parameter(Mandatory)][string[]] $Formats
  )

  $hasUnicode = $Formats -contains 'UnicodeText'
  $hasText    = $Formats -contains 'Text'
  $hasHtml    = $Formats -contains 'HTML Format'
  $hasRtf     = $Formats -contains 'Rich Text Format'

  if ($hasUnicode) {
    return [string]$DataObject.GetData('UnicodeText')
  }

  if ($hasText) {
    return [string]$DataObject.GetData('Text')
  }

  if ($hasHtml) {
    $raw = [string]$DataObject.GetData('HTML Format')
    return Convert-HtmlFormatToText -HtmlFormat $raw
  }

  if ($hasRtf) {
    $raw = [string]$DataObject.GetData('Rich Text Format')
    return Convert-RtfToText -Rtf $raw
  }

  return $null
}

function Normalize-Text {
  param([Parameter(Mandatory)][string] $Text)

  # Normalize to LF
  $t = $Text -replace "`r`n", "`n"
  $t = $t -replace "`r", "`n"

  # Trim leading/trailing whitespace including newlines
  $t = $t.Trim()

  # Collapse 3+ blank lines to 2 (preserve paragraphs)
  $t = [regex]::Replace($t, "`n{3,}", "`n`n")

  # Convert to CRLF
  $t = $t -replace "`n", "`r`n"

  return $t
}

# ---- Main ----

$data = Get-ClipboardDataObject
if (-not $data) {
  Fail-AndPause -Message "Clipboard returned no data object." -ExitCode 1
}

$formats = Get-AvailableFormats -DataObject $data

$hasAnyText =
  ($formats -contains 'UnicodeText') -or
  ($formats -contains 'Text') -or
  ($formats -contains 'HTML Format') -or
  ($formats -contains 'Rich Text Format')

if (-not $hasAnyText) {
  Fail-AndPause -Message "Clipboard contains no text formats (likely files or images). Nothing modified." -ExitCode 2
}

$extracted = Get-TextFromDataObject -DataObject $data -Formats $formats
if (-not $extracted -or [string]::IsNullOrWhiteSpace($extracted)) {
  Fail-AndPause -Message "Text extraction failed or resulted in empty content. Nothing modified." -ExitCode 3
}

$clean = Normalize-Text -Text $extracted

try {
  Ensure-WinForms
  [System.Windows.Forms.Clipboard]::SetText($clean, [System.Windows.Forms.TextDataFormat]::UnicodeText)
} catch {
  Fail-AndPause -Message "Failed to write sanitized text back to clipboard." -ExitCode 4
}

exit 0