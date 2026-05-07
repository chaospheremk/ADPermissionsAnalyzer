# Changelog

All notable changes to ADPermissionsAnalyzer are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `scripts/Invoke-ADPermissionAnalysis.ps1` — entry-point script skeleton (plan
  §18.1): full parameter surface, JSONL logging primitive (`Write-LogEvent`),
  and top-level execution flow with deterministic exit codes (0 / 1 / 2). Phase
  bodies are stubbed pending §18.2-§18.8.

### Changed

### Fixed
