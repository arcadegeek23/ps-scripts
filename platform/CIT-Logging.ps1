# CIT-Logging.ps1
# Shared logging helpers for all CIT Intune scripts.
# Source with: . "$PSScriptRoot\..\platform\CIT-Logging.ps1" -ScriptName 'MyScript'
#
# Logs to: C:\ProgramData\CIT\Logs\<ScriptName>.log
# Format:  YYYY-MM-DD HH:mm:ss.fff [LEVEL] [ScriptName] message

function Write-CITLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Message,
        [Parameter()] [ValidateSet('INFO','WARN','ERROR','DEBUG')] [string] $Level = 'INFO',
        [Parameter(Mandatory)] [string] $ScriptName
    )

    $logDir = 'C:\ProgramData\CIT\Logs'
    if (-not (Test-Path $logDir)) {
        try { New-Item -Path $logDir -ItemType Directory -Force | Out-Null } catch { return }
    }

    $ts   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $line = "$ts [$Level] [$ScriptName] $Message"
    Add-Content -Path (Join-Path $logDir "$ScriptName.log") -Value $line -Encoding UTF8
}

# Run a script block and emit a structured error to the log on failure.
# Returns $true if the block succeeded, $false otherwise.
function Invoke-CITSafely {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [scriptblock] $ScriptBlock,
        [Parameter(Mandatory)] [string]     $ScriptName,
        [Parameter()]    [string]     $Context = ''
    )

    try {
        & $ScriptBlock
        return $true
    } catch {
        $msg = if ($Context) { "$Context failed: $($_.Exception.Message)" } else { $_.Exception.Message }
        Write-CITLog -Message $msg -Level ERROR -ScriptName $ScriptName
        return $false
    }
}
