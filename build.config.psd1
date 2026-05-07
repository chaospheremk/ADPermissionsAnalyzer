# Build configuration for ADPermissionsAnalyzer
# Consumed by ADPermissionsAnalyzer.build.ps1 — all paths are relative to the repo root.
@{
    ProjectName       = 'ADPermissionsAnalyzer'
    TestsDir          = 'Tests'
    OutputDir         = 'output'
    PSSASettingsPath  = 'PSScriptAnalyzerSettings.psd1'

    # ScanPaths feeds Lint; CoveragePaths feeds Pester code coverage.
    # 'scripts' is recursive on disk and covers scripts/lib/* as well.
    ScanPaths         = @('scripts', 'Export-ScriptDocumentation.ps1')
    CoveragePaths     = @('scripts')

    # Threshold is 0 until tests catch up (see plan §17/§18 mapping table).
    # Bump as Pester coverage grows during each implementation step.
    CoverageThreshold = 0
    CoverageFormat    = 'JaCoCo'
}
