#Requires -Version 7.0
#Requires -Modules InvokeBuild

<#
.SYNOPSIS
    Build script for ADPermissionsAnalyzer. Run with: Invoke-Build [Task] [-Configuration <Debug|Release>]
#>

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Debug'
)

# --- Config -----------------------------------------------------------------

$Config       = Import-PowerShellDataFile "$PSScriptRoot/build.config.psd1"
$ProjectName  = $Config.ProjectName
$TestsDir     = Join-Path $PSScriptRoot $Config.TestsDir
$OutputDir    = Join-Path $PSScriptRoot $Config.OutputDir

# --- Tasks ------------------------------------------------------------------

task Clean {
    if (Test-Path $OutputDir) { Remove-Item $OutputDir -Recurse -Force }
    New-Item $OutputDir -ItemType Directory | Out-Null
}

task Lint {
    $scanPaths = $Config.ScanPaths | ForEach-Object {
        Join-Path $PSScriptRoot $_
    } | Where-Object { Test-Path $_ }

    $settingsPath = Join-Path $PSScriptRoot $Config.PSSASettingsPath
    $results = foreach ($scanPath in $scanPaths) {
        $pssaParams = @{
            Path     = $scanPath
            Recurse  = $true
            Settings = $settingsPath
        }
        Invoke-ScriptAnalyzer @pssaParams
    }
    if ($results) {
        foreach ($r in $results) {
            Write-Warning "[$($r.Severity)] $($r.RuleName) — $($r.ScriptName):$($r.Line)"
        }
        throw "PSScriptAnalyzer found $($results.Count) issue(s). Fix before proceeding."
    }
}

task Test {
    if (-not (Test-Path $TestsDir)) {
        Write-Build Yellow "No Tests directory at $TestsDir — skipping."
        return
    }

    $pesterConfig = New-PesterConfiguration
    $pesterConfig.Run.Path = $TestsDir
    $pesterConfig.Run.PassThru = $true
    $pesterConfig.Output.Verbosity = 'Detailed'

    $pesterConfig.TestResult.Enabled = $true
    $pesterConfig.TestResult.OutputFormat = 'JUnitXml'
    $pesterConfig.TestResult.OutputPath = Join-Path $PSScriptRoot 'TestResults.xml'

    $pesterConfig.CodeCoverage.Enabled = ($Configuration -eq 'Release')
    $pesterConfig.CodeCoverage.OutputFormat = $Config.CoverageFormat
    $pesterConfig.CodeCoverage.OutputPath = Join-Path $PSScriptRoot 'CoverageResults.xml'
    $pesterConfig.CodeCoverage.Path = $Config.CoveragePaths | ForEach-Object {
        Join-Path $PSScriptRoot $_
    }

    $result = Invoke-Pester -Configuration $pesterConfig
    assert ($result.FailedCount -eq 0) "Pester: $($result.FailedCount) test(s) failed."

    if ($Configuration -eq 'Release') {
        $threshold = $Config.CoverageThreshold
        $coveragePct = [math]::Round($result.CodeCoverage.CoveragePercent, 2)
        Write-Build Green "Code coverage: $coveragePct% (threshold: $threshold%)"
        assert ($coveragePct -ge $threshold) "Coverage $coveragePct% is below the $threshold% threshold."
    }
}

# ---------------------------------------------------------------------------
# Composite tasks
# ---------------------------------------------------------------------------

task Build Clean, Lint, Test
task .     Build
