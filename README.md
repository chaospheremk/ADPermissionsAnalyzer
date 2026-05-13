# ADPermissionsAnalyzer

[![CI](https://github.com/chaospheremk/ADPermissionsAnalyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/chaospheremk/ADPermissionsAnalyzer/actions/workflows/ci.yml)
[![Docs](https://github.com/chaospheremk/ADPermissionsAnalyzer/actions/workflows/docs.yml/badge.svg)](https://github.com/chaospheremk/ADPermissionsAnalyzer/actions/workflows/docs.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

PowerShell 7+ tool that produces a comprehensive inventory of every DACL ACE on every object in a single Active Directory domain, across all naming contexts (Domain, Configuration, Schema, DNS application partitions). Intended for AD administrators and security engineers performing least-privilege review.

**[Documentation site](https://chaospheremk.github.io/ADPermissionsAnalyzer/)** | **[Operator runbook](docs/operator-runbook.md)** | **[Design spec](docs/AD-Permissions-Analyzer-Plan.md)** | **[Changelog](CHANGELOG.md)**

## What it produces

- **Detail CSV** — one row per (ACE × effective trustee), with full GUID-resolved object/property names, decoded rights, group-expansion path, and inheritance source DN. ~30 columns; see the [design spec §11](docs/AD-Permissions-Analyzer-Plan.md) for the full schema.
- **Pivot CSV** — one row per effective trustee, with aggregate counts, rights summary, and object/NC breadth touched.
- **JSONL run log** — structured events (`ScriptStart`, `PhaseStart`/`PhaseEnd`, `OrphanSid`, `BatchError`, `ScriptEnd`) with timings, counts, and errors. Suitable for ingestion into a SIEM or log analyzer.

## Prerequisites

- PowerShell 7.0 or later, on Windows. The script uses `System.DirectoryServices.ActiveDirectorySecurity` and `NTAccount.Translate()`; neither is available on .NET on Linux or macOS.
- Network reachability to a writable domain controller on TCP/389 (LDAP). LDAPS (636) is not used in v1.
- Read access to the `nTSecurityDescriptor` attribute on every object in the enumerated naming contexts. This is typically Domain Admins or an explicitly delegated principal — most accounts cannot read SDs by default.
- Kerberos (Negotiate) authentication; NTLM fallback is acceptable.

## Quick start

Minimal — run against the current domain with defaults:

```powershell
.\scripts\Invoke-ADPermissionAnalysis.ps1 -OutputDirectory C:\AdPermAudit
```

Targeted — specific domain, specific DC, limited NCs, fixed thread count:

```powershell
$params = @{
    Domain                = 'corp.example.com'
    Server                = 'dc01.corp.example.com'
    OutputDirectory       = 'C:\AdPermAudit'
    ThreadCount           = 8
    IncludeNamingContexts = @('Domain', 'Configuration')
}
.\scripts\Invoke-ADPermissionAnalysis.ps1 @params
```

Before running against a production directory, read the [operator runbook](docs/operator-runbook.md) — it covers pre-flight checks, expected event counts, JSONL decoding, and failure modes for the first live-LDAP run.

Exit codes: `0` success, `1` unrecoverable error, `2` success-with-warnings (partial inventory written; review the JSONL log for `BatchError` / `PARSE_ERROR` / `OrphanSid`).

## Scripts

| Script | Description |
|---|---|
| `scripts/Invoke-ADPermissionAnalysis.ps1` | Entry point. Orchestrates all six phases per the design spec. |
| `scripts/Install-GitHooks.ps1` | Developer setup helper — installs the local pre-commit hook. |

The phase implementations live under `scripts/lib/Phase{1..6}-*.ps1` and are dot-sourced by the entry script; they are not invoked directly.

Generated comment-based-help reference for every exported function is published at the [documentation site](https://chaospheremk.github.io/ADPermissionsAnalyzer/) (rebuilt on every push to `main`).

## Development setup

```powershell
# Pre-commit hooks (TruffleHog secret scanning) — one-time per clone
pip install pre-commit
pre-commit install

# Or install the project's git hooks directly
.\scripts\Install-GitHooks.ps1
```

Build, lint, and test:

```powershell
Invoke-Build Build -Configuration Release   # PSScriptAnalyzer + Pester + coverage gate
Invoke-Pester ./Tests                        # tests only
```

Coverage is gated at 86% on `scripts/lib/` (see [`build.config.psd1`](build.config.psd1)).

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the branching model, local setup, style rules, and PR checklist.

## Security

To report a security issue, see [SECURITY.md](SECURITY.md). Please do not open a public issue for vulnerabilities.

## License

MIT — see [LICENSE](LICENSE).
