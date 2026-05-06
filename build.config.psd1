# Build configuration for ADPermissionsAnalyzer
# Consumed by ADPermissionsAnalyzer.build.ps1 — all paths are relative to the repo root.
@{
    ProjectName       = 'ADPermissionsAnalyzer'
    TestsDir          = 'Tests'                # CUSTOMIZATION: match your actual directory casing
    OutputDir         = 'output'
    PSSASettingsPath  = 'PSScriptAnalyzerSettings.psd1'

    # CUSTOMIZATION: list each top-level script file once the planning phase defines them.
    # ScanPaths feeds Lint; CoveragePaths feeds Pester code coverage.
    ScanPaths         = @('scripts')
    CoveragePaths     = @('scripts')

    CoverageThreshold = 50
    CoverageFormat    = 'JaCoCo'
}
