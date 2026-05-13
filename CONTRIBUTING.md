# Contributing

Thanks for your interest in ADPermissionsAnalyzer. Bug reports, feature requests, documentation improvements, and code contributions are all welcome.

## Branching model — trunk-based

`main` is the only long-lived branch and is always green.

For any change:

1. Update your local `main`: `git switch main && git pull origin main`.
2. Create a short-lived branch off `main`:
   - `feat/<topic>` for new features
   - `fix/<topic>` for bug fixes
   - `docs/<topic>` for docs-only changes
   - `chore/<topic>` for build, CI, or repo metadata
3. Make commits, push the branch: `git push -u origin <branch>`.
4. Open a PR against `main`. CI must be green.
5. After merge, delete the branch (locally and on the remote):
   ```powershell
   git switch main; git pull
   git branch -D <branch>
   git push origin --delete <branch>
   ```

Never commit directly to `main`.

> The project's git history before 2026-05-13 used a permanent `dev` branch and merged `dev → main`. That model has been retired — older commit-message references to `dev` are historical only.

## Local setup

```powershell
git clone https://github.com/chaospheremk/ADPermissionsAnalyzer.git
cd ADPermissionsAnalyzer

# Pre-commit hooks (TruffleHog secret scan)
pip install pre-commit
pre-commit install

# Optional: install local git hooks via the bundled installer
.\scripts\Install-GitHooks.ps1
```

## Build and test

```powershell
Invoke-Build Build -Configuration Release   # lint + tests + coverage gate
Invoke-Pester ./Tests                        # tests only
Invoke-ScriptAnalyzer -Path . -Recurse -Settings PSScriptAnalyzerSettings.psd1
```

Coverage is scoped to `scripts/lib/` and gated at 86%. New code in `scripts/lib/` should ship with Pester coverage; the entry script (`scripts/Invoke-ADPermissionAnalysis.ps1`) is excluded from the gate because it is integration-test surface (no lab DC is available — see the design spec §17).

## Style

The full house style is enforced by `PSScriptAnalyzerSettings.psd1`. Highlights:

- PowerShell 7+ only — `#Requires -Version 7.0`.
- Prefer `foreach` over `ForEach-Object` and `.Where({})` over `Where-Object`.
- Typed collections (`[List[T]]`, `[Dictionary[K,V]]`, `[HashSet[T]]`).
- `[CmdletBinding()]` on every function. Approved verbs only (`Get-`, `New-`, `Resolve-`, `Write-LogEvent`, etc. — `Write-Log` would fail `PSUseApprovedVerbs`).
- No `Set-StrictMode`. No `Write-Host` (use `Write-Progress` for progress and `Write-LogEvent` for JSONL).
- Splatting for any call with 3 or more parameters. No backtick line continuation.
- All parameters use placeholder values in examples (`<domain.fqdn>`, `<dc-fqdn>`) — never real identifiers.

## Tests

Tests live under `Tests/` and use Pester 5 syntax with `Describe`/`Context`/`It` blocks. Fixtures use clearly-fake values:

- DNs: `DC=lab,DC=local`
- SIDs: `S-1-5-21-100-200-300-<rid>`
- GUIDs: `11111111-1111-1111-1111-111111111111` style placeholders

Never commit real directory data, real SIDs, real hostnames, or real principal names.

When asserting on collections, remember to comma-wrap to bypass pipeline unrolling: `, $value | Should -BeOfType ([List[T]])`. See `ADR-005` in the changelog for context.

## Commits

This repo uses [Conventional Commits](https://www.conventionalcommits.org/). Prefixes in use:

- `feat:` new functionality
- `fix:` bug fixes
- `docs:` documentation only
- `chore:` build, CI, repo metadata
- `chore(release):` version tags

The changelog (`CHANGELOG.md`) follows [Keep a Changelog](https://keepachangelog.com/). Add an entry under `[Unreleased]` in your PR when the change is user-visible.

## Pull request checklist

Before requesting review:

- [ ] PSScriptAnalyzer clean.
- [ ] Pester tests pass and coverage has not regressed below 86% on `scripts/lib/`.
- [ ] `CHANGELOG.md` updated under `[Unreleased]` if the change is user-visible.
- [ ] Comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`) updated for any new or changed public function.
- [ ] No real directory data in tests, fixtures, or examples.
- [ ] Relevant ADRs cited in the PR description, if applicable. (ADRs live in the maintainer's notes; their numbers appear in the changelog and in commit messages.)

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree to abide by its terms.

## Security

To report a vulnerability, follow the process in [SECURITY.md](SECURITY.md). Do not open a public issue for security problems.
