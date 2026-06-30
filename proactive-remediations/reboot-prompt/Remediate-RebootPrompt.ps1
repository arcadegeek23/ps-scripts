#Requires -Version 5.1
# Remediate-RebootPrompt.ps1
# Shows an interactive WPF dialog prompting the user to reboot now or postpone.
# Intune Proactive Remediation runs as SYSTEM, so this script creates a
# one-shot Scheduled Task that launches the UI in the logged-in user's session.
#
# If the user clicks "Reboot Now" -> shutdown /r /t 60 (60s grace to save work)
# If the user clicks "Postpone"   -> writes cooldown timestamp to registry
# If the timer hits 0             -> auto-reboots
#
# The detection script respects the cooldown (4h default), so the prompt
# refires on the next Intune schedule tick after cooldown expires.
#
# Author:  Kyle Etter / Zeus
# Created: 2026-06-30
# Intune:  Proactive Remediation - Remediation

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# --- Inline logging -------------------------------------------------------------
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

$ScriptName = 'Remediate-RebootPrompt'

# --- Configuration --------------------------------------------------------------
$CountdownSeconds = 600   # 10-minute countdown before auto-reboot
$RebootGraceSec   = 60    # grace period after "Reboot Now" or timer expiry

# Registry paths (shared with detect script)
$CooldownRegPath = 'HKLM:\SOFTWARE\CIT\RebootPrompt'
$CooldownRegName = 'LastPostpone'

# --- WPF dialog script (runs in user session via Scheduled Task) ----------------
# This is embedded as a here-string and written to a temp file, then launched
# as the logged-in user via a one-shot Scheduled Task. This is the standard
# pattern for showing interactive UI from a SYSTEM-context Intune remediation.

$dialogScript = @'
#Requires -Version 5.1
# RebootPrompt-Dialog.ps1 - launched in user session by Intune remediation
param(
    [int]$CountdownSeconds = 600,
    [int]$RebootGraceSec   = 60
)

$ErrorActionPreference = 'Stop'

# Load WPF assemblies
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Xaml

$CooldownRegPath = 'HKLM:\SOFTWARE\CIT\RebootPrompt'
$CooldownRegName = 'LastPostpone'

# --- Build the WPF window ---
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="CIT - Restart Required"
        Height="260" Width="480"
        WindowStartupLocation="CenterScreen"
        Topmost="True"
        ResizeMode="NoResize"
        WindowStyle="SingleBorderWindow"
        Background="#1E1E2E">
    <Window.Resources>
        <Style x:Key="BtnReboot" TargetType="Button">
            <Setter Property="Background" Value="#0078D4"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="Padding" Value="20,8"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#006ABC"/>
                </Trigger>
            </Style.Triggers>
        </Style>
        <Style x:Key="BtnPostpone" TargetType="Button">
            <Setter Property="Background" Value="#3D3D52"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontWeight" Value="Normal"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="Padding" Value="20,8"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#4D4D62"/>
                </Trigger>
            </Style.Triggers>
        </Style>
    </Window.Resources>
    <Grid Margin="24">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <TextBlock Grid.Row="0" Text="Restart Required"
                   Foreground="White" FontSize="20" FontWeight="Bold"
                   Margin="0,0,0,8"/>

        <TextBlock Grid.Row="1" TextWrapping="Wrap"
                   Foreground="#CCCCCC" FontSize="14"
                   Margin="0,0,0,12">
            Your device needs a restart to complete installed updates.
            Please save your work and restart now, or postpone to be
            reminded later.
        </TextBlock>

        <TextBlock Grid.Row="2" Name="CountdownLabel"
                   Foreground="#FFA500" FontSize="16" FontWeight="SemiBold"
                   HorizontalAlignment="Center" Margin="0,4,0,8"/>

        <StackPanel Grid.Row="4" Orientation="Horizontal"
                    HorizontalAlignment="Center" Margin="0,8,0,0">
            <Button Name="BtnReboot" Content="Restart Now"
                    Style="{StaticResource BtnReboot}"
                    Margin="0,0,16,0"/>
            <Button Name="BtnPostpone" Content="Postpone"
                    Style="{StaticResource BtnPostpone}"/>
        </StackPanel>
    </Grid>
</Window>
"@

$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [System.Windows.Markup.XamlReader]::Load($reader)

# Find controls
$btnReboot   = $window.FindName('BtnReboot')
$btnPostpone = $window.FindName('BtnPostpone')
$lblCountdown = $window.FindName('CountdownLabel')

# --- Countdown timer ---
$script:secondsLeft = $CountdownSeconds
$script:userActed   = $false

$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(1)
$timer.Add_Tick({
    $script:secondsLeft--
    if ($script:secondsLeft -le 0) {
        $script:userActed = $true
        $timer.Stop()
        $window.Close()
        # Auto-reboot: grace period to let the UI close cleanly
        Start-Process -FilePath 'shutdown.exe' -ArgumentList "/r /t $RebootGraceSec /c `"CIT: Automatic restart to complete updates. Please save your work.`""
        return
    }
    $mins = [math]::Floor($script:secondsLeft / 60)
    $secs = $script:secondsLeft % 60
    $lblCountdown.Text = "Auto-restart in {0:D2}:{1:D2}" -f $mins, $secs
})

# Update initial label
$mins = [math]::Floor($script:secondsLeft / 60)
$secs = $script:secondsLeft % 60
$lblCountdown.Text = "Auto-restart in {0:D2}:{1:D2}" -f $mins, $secs

# --- Button handlers ---
$btnReboot.Add_Click({
    $script:userActed = $true
    $timer.Stop()
    $window.Close()
    Start-Process -FilePath 'shutdown.exe' -ArgumentList "/r /t $RebootGraceSec /c `"CIT: Restarting now to complete updates. Please save your work.`""
})

$btnPostpone.Add_Click({
    $script:userActed = $true
    $timer.Stop()
    # Write cooldown timestamp
    try {
        if (-not (Test-Path $CooldownRegPath)) {
            New-Item -Path $CooldownRegPath -Force | Out-Null
        }
        Set-ItemProperty -Path $CooldownRegPath -Name $CooldownRegName -Value (Get-Date).ToString('o') -Type String
    } catch {}
    $window.Close()
})

$window.Add_Closing({
    if (-not $script:userActed) {
        # Window was closed via X button - treat as postpone
        $timer.Stop()
        try {
            if (-not (Test-Path $CooldownRegPath)) {
                New-Item -Path $CooldownRegPath -Force | Out-Null
            }
            Set-ItemProperty -Path $CooldownRegPath -Name $CooldownRegName -Value (Get-Date).ToString('o') -Type String
        } catch {}
    }
})

# --- Show the dialog ---
$timer.Start()
$window.ShowDialog() | Out-Null
'@

# --- Main: create scheduled task to launch dialog in user session ----------------

try {
    Write-CITLog -Message 'Starting reboot prompt remediation' -Level INFO -ScriptName $ScriptName

    # 1. Find the active console user
    $activeUser = $null
    try {
        # query user returns usernames of active sessions
        $queryResult = (query user 2>$null) | Select-Object -Skip 1
        if ($queryResult) {
            # Parse "USERNAME SESSIONNAME ID STATE" - take the first Active console user
            foreach ($line in $queryResult) {
                $parts = $line -split '\s+' | Where-Object { $_ }
                if ($parts.Count -ge 4 -and $parts[3] -match 'Active') {
                    $activeUser = $parts[0]
                    break
                }
            }
        }
    } catch {}

    if (-not $activeUser) {
        # No active user session - reboot silently after a short delay
        Write-CITLog -Message 'No active user session found - scheduling silent reboot in 5 minutes' -Level WARN -ScriptName $ScriptName
        Start-Process -FilePath 'shutdown.exe' -ArgumentList '/r /t 300 /c "CIT: Restart required to complete updates. No user session active, rebooting in 5 minutes."'
        exit 0
    }

    Write-CITLog -Message "Active user: $activeUser - launching interactive reboot prompt" -Level INFO -ScriptName $ScriptName

    # 2. Write the dialog script to a temp location
    $dialogPath = 'C:\ProgramData\CIT\RebootPrompt-Dialog.ps1'
    $dialogDir  = Split-Path $dialogPath
    if (-not (Test-Path $dialogDir)) {
        New-Item -Path $dialogDir -ItemType Directory -Force | Out-Null
    }
    Set-Content -Path $dialogPath -Value $dialogScript -Encoding UTF8

    # 3. Create a one-shot Scheduled Task that runs as the active user
    #    This is the standard pattern for showing UI from SYSTEM context.
    $taskName = "CIT-RebootPrompt-$(Get-Date -Format 'yyyyMMddHHmmss')"

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dialogPath`" -CountdownSeconds $CountdownSeconds -RebootGraceSec $RebootGraceSec"

    # Run as the active user with interactive enabled
    $principal = New-ScheduledTaskPrincipal -UserId "$activeUser" -LogonType Interactive -RunLevel Limited

    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 15) -DeleteExpiredTaskAfter (New-TimeSpan -Minutes 30)

    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(2)

    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal `
        -Settings $settings -Trigger $trigger -Force | Out-Null

    # 4. Start the task immediately
    Start-ScheduledTask -TaskName $taskName

    Write-CITLog -Message "Scheduled task '$taskName' created and started for user $activeUser" -Level INFO -ScriptName $ScriptName

    # 5. Cleanup: schedule the task for deletion after 30 min (in case it hangs)
    $cleanupTaskName = "CIT-RebootPrompt-Cleanup-$(Get-Date -Format 'yyyyMMddHHmmss')"
    $cleanupAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -Command `"Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName '$cleanupTaskName' -Confirm:`$false -ErrorAction SilentlyContinue`""
    $cleanupPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $cleanupTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(30)
    $cleanupSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -DeleteExpiredTaskAfter (New-TimeSpan -Minutes 5)
    Register-ScheduledTask -TaskName $cleanupTaskName -Action $cleanupAction -Principal $cleanupPrincipal `
        -Settings $cleanupSettings -Trigger $cleanupTrigger -Force | Out-Null

    Write-CITLog -Message "Cleanup task scheduled for +30 min" -Level INFO -ScriptName $ScriptName
    Write-Output "PromptLaunched=1;User=$activeUser;Countdown=$CountdownSeconds`s"
    exit 0

} catch {
    Write-CITLog -Message "Remediation error: $($_.Exception.Message)" -Level ERROR -ScriptName $ScriptName
    exit 2
}