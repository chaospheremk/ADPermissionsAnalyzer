# Build configuration for ADPermissionsAnalyzer
# Consumed by ADPermissionsAnalyzer.build.ps1 — all paths are relative to the repo root.
@{
    ProjectName       = 'ADPermissionsAnalyzer'
    TestsDir          = 'Tests'
    OutputDir         = 'output'
    PSSASettingsPath  = 'PSScriptAnalyzerSettings.psd1'

    # ScanPaths feeds Lint (full surface); CoveragePaths feeds Pester code
    # coverage. Coverage scope is scripts/lib/ only — the entry script and
    # Install-GitHooks are excluded by ADR-026 (integration-test / utility
    # surface, not unit-testable).
    ScanPaths         = @('scripts', 'Export-ScriptDocumentation.ps1')
    CoveragePaths     = @('scripts/lib')

    # 5pp below the measured lib floor (91.22%) per ADR-026; high enough to
    # lock in current coverage, low enough to absorb a single new helper
    # without immediately breaking CI.
    CoverageThreshold = 86
    CoverageFormat    = 'JaCoCo'
}
