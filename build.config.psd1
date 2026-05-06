# Build configuration for ADPermissionsAnalyzer
# Consumed by ADPermissionsAnalyzer.build.ps1 — all paths are relative to the repo root.
@{
    ProjectName       = 'ADPermissionsAnalyzer'
    TestsDir          = 'Tests'
    OutputDir         = 'output'
    PSSASettingsPath  = 'PSScriptAnalyzerSettings.psd1'

    # ScanPaths feeds Lint; CoveragePaths feeds Pester code coverage.
    # TODO: extend with the analyzer script paths once defined (see docs/AD-Permissions-Analyzer-Plan.md §18).
    # 'scripts' currently covers only Install-GitHooks.ps1 — adequate as a starting point.
    ScanPaths         = @('scripts')
    CoveragePaths     = @('scripts')

    CoverageThreshold = 50
    CoverageFormat    = 'JaCoCo'
}
