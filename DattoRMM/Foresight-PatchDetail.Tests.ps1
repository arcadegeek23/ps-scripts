BeforeAll {
  $scriptPath = Join-Path $PSScriptRoot "Foresight-PatchDetail.ps1"
  $scriptContent = Get-Content -Path $scriptPath -Raw
  $tokens = $null
  $parseErrors = $null
  $scriptAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath,
    [ref]$tokens,
    [ref]$parseErrors
  )
  foreach ($functionName in @(
    "Set-DattoUdf",
    "Get-UpdateClass",
    "Get-KbToken",
    "Get-FailedUpdateIds",
    "Get-FailedEntryToken",
    "New-PatchDetailPayload"
  )) {
    $functionAst = $scriptAst.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq $functionName
    }, $true)
    Invoke-Expression $functionAst.Extent.Text
  }
}

Describe "Foresight patch-detail Datto UDF contract" {
  BeforeEach {
    $script:payload = "PD1|s=2026-07-11|rb=0|rs=-|mc=0|cc=0|fc=0|dc=0|oc=0|dfc=0|t=0|m=|f="

    Mock Test-Path { $true }
    Mock New-Item { }
    Mock New-ItemProperty {
      $result = [pscustomobject]@{}
      $result | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
      return $result
    }
    Mock Get-ItemPropertyValue { $script:payload }
  }

  It "parses without errors and targets UDF 20" {
    $parseErrors.Count | Should -Be 0
    $scriptContent | Should -Match '(?m)^\s*\$UdfSlot\s*=\s*20\s*$'
  }

  It "passes the encoded PD1 payload to the Datto writer" {
    $scriptContent | Should -Match '(?m)^\s*\$FormatVersion\s*=\s*"PD1"\s*$'
    $scriptContent | Should -Match '(?m)^\s*\$writeStatus\s*=\s*Set-DattoUdf\s+-Slot\s+\$UdfSlot\s+-Value\s+\$encoded\s*$'
    $scriptContent | Should -Not -Match '(?i)DeviceID'
  }

  It "separates driver, optional, and definition updates from scored updates" {
    Get-UpdateClass ([pscustomobject]@{
      Type = 2
      Categories = @()
      BrowseOnly = $true
    }) | Should -Be "Driver"

    Get-UpdateClass ([pscustomobject]@{
      Type = 1
      Categories = @()
      BrowseOnly = $true
    }) | Should -Be "Optional"

    Get-UpdateClass ([pscustomobject]@{
      Type = 1
      Categories = @([pscustomobject]@{
        Name = "Actualizaciones de definiciones"
        CategoryID = "E0789628-CE08-4437-BE74-2495B842F43B"
      })
      BrowseOnly = $false
    }) | Should -Be "Definition"

    Get-UpdateClass ([pscustomobject]@{
      Type = 1
      Categories = @([pscustomobject]@{ Name = "Security Updates" })
      BrowseOnly = $false
    }) | Should -Be "Scored"
  }

  It "counts failed history only for currently pending scored updates" {
    $history = @(
      [pscustomobject]@{ ResultCode = 4; Operation = 1; UpdateIdentity = [pscustomobject]@{ UpdateID = "driver" } },
      [pscustomobject]@{ ResultCode = 4; Operation = 1; UpdateIdentity = [pscustomobject]@{ UpdateID = "optional" } },
      [pscustomobject]@{ ResultCode = 4; Operation = 1; UpdateIdentity = [pscustomobject]@{ UpdateID = "definition" } },
      [pscustomobject]@{ ResultCode = 4; Operation = 1; UpdateIdentity = [pscustomobject]@{ UpdateID = "scored" } },
      [pscustomobject]@{ ResultCode = 4; Operation = 1; UpdateIdentity = [pscustomobject]@{ UpdateID = "scored" } },
      [pscustomobject]@{ ResultCode = 4; Operation = 1; UpdateIdentity = [pscustomobject]@{ UpdateID = "not-pending" } },
      [pscustomobject]@{ ResultCode = 2; Operation = 1; UpdateIdentity = [pscustomobject]@{ UpdateID = "successful" } }
    )
    $failedUpdateIds = Get-FailedUpdateIds $history

    $pending = @(
      [pscustomobject]@{
        Type = 2
        Categories = @()
        BrowseOnly = $false
        Identity = [pscustomobject]@{ UpdateID = "driver" }
        KBArticleIDs = @()
        Title = "Driver Update"
      },
      [pscustomobject]@{
        Type = 1
        Categories = @()
        BrowseOnly = $true
        Identity = [pscustomobject]@{ UpdateID = "optional" }
        KBArticleIDs = @()
        Title = "Optional Update"
      },
      [pscustomobject]@{
        Type = 1
        Categories = @([pscustomobject]@{
          Name = "Actualizaciones de definiciones"
          CategoryID = "E0789628-CE08-4437-BE74-2495B842F43B"
        })
        BrowseOnly = $false
        Identity = [pscustomobject]@{ UpdateID = "definition" }
        KBArticleIDs = @()
        Title = "Definition Update"
      },
      [pscustomobject]@{
        Type = 1
        Categories = @([pscustomobject]@{ Name = "Security Updates" })
        BrowseOnly = $false
        Identity = [pscustomobject]@{ UpdateID = "scored" }
        KBArticleIDs = @()
        Title = "Security Update KB5000001"
      },
      [pscustomobject]@{
        Type = 1
        Categories = @([pscustomobject]@{ Name = "Security Updates" })
        BrowseOnly = $false
        Identity = [pscustomobject]@{ UpdateID = "clean" }
        KBArticleIDs = @()
        Title = "Security Update KB5000002"
      }
    )

    $failedEntries = @()
    foreach ($update in $pending) {
      $updateClass = Get-UpdateClass $update
      $failedEntry = Get-FailedEntryToken $update $updateClass $failedUpdateIds
      if ($failedEntry) { $failedEntries += $failedEntry }
    }

    $failedUpdateIds.Count | Should -Be 5
    $failedEntries.Count | Should -Be 1
    $failedEntries[0] | Should -Match '^SecurityUpdateKB5000~I~-$'
  }

  It "keeps exact totals and trims names to the Datto UDF limit" {
    $missingEntries = @(1..75 | ForEach-Object {
      "500$($_.ToString('0000'))~I~2026-01-01"
    })

    $value = New-PatchDetailPayload `
      -Version "PD1" `
      -ScanDate "2026-07-11" `
      -RebootFlag 0 `
      -MissingTotal 75 `
      -CriticalTotal 10 `
      -FailedTotal 0 `
      -DriverTotal 20 `
      -OptionalTotal 5 `
      -DefinitionTotal 3 `
      -MissingEntries $missingEntries `
      -FailedEntries @() `
      -MaxEntries 12 `
      -MaxLength 255

    $value.Length | Should -BeLessOrEqual 255
    $value | Should -Match '\|mc=75\|cc=10\|fc=0\|dc=20\|oc=5\|dfc=3\|t=1\|'
    $value | Should -Match '5000001~I~2026-01-01'
  }

  It "writes and reads back the exact PD1 value in Custom20" {
    Set-DattoUdf -Slot 20 -Value $script:payload | Should -Be "verified"

    Should -Invoke New-ItemProperty -Times 1 -Exactly -ParameterFilter {
      $Path -eq "HKLM:\SOFTWARE\CentraStage" -and
        $Name -eq "Custom20" -and
        $PropertyType -eq "String" -and
        $Value -ceq $script:payload -and
        $Force
    }
    Should -Invoke Get-ItemPropertyValue -Times 1 -Exactly -ParameterFilter {
      $Path -eq "HKLM:\SOFTWARE\CentraStage" -and $Name -eq "Custom20"
    }
  }

  It "rejects a device UID before touching the registry" {
    { Set-DattoUdf -Slot 20 -Value "3e35bf7c-7a51-5c85-e003-f8a7a0ba53c7" } |
      Should -Throw "*non-PD1*"

    Should -Invoke New-ItemProperty -Times 0 -Exactly
  }

  It "fails when a present registry value does not match the payload" {
    Mock Get-ItemPropertyValue { "wrong-value" }

    { Set-DattoUdf -Slot 20 -Value $script:payload } |
      Should -Throw "*read-back verification failed*Custom20*"
  }

  It "accepts an already-consumed value after the verified write" {
    Mock Get-ItemPropertyValue {
      throw [System.Management.Automation.PSArgumentException]::new("Property already consumed")
    }

    Set-DattoUdf -Slot 20 -Value $script:payload |
      Should -Be "consumed by the Datto agent"
  }
}
