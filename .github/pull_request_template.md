<!--
Thanks for the PR. Please fill in the sections below.
Delete any sections that genuinely do not apply.
-->

## Summary

<!-- One or two sentences describing what this PR changes and why. -->

## Related issue / ADR

<!-- e.g. "Closes #42" or "Implements ADR-029". -->

## Type of change

- [ ] `feat` — new functionality
- [ ] `fix` — bug fix
- [ ] `docs` — documentation only
- [ ] `chore` — build, CI, repo metadata
- [ ] Breaking change (describe migration below)

## Test plan

<!-- How did you verify this? Which Pester tests cover the change? Any manual steps? -->

## Checklist

- [ ] PSScriptAnalyzer clean (`Invoke-ScriptAnalyzer -Path . -Recurse -Settings PSScriptAnalyzerSettings.psd1`)
- [ ] Pester tests pass (`Invoke-Pester ./Tests`)
- [ ] Coverage has not regressed below 86% on `scripts/lib/`
- [ ] `CHANGELOG.md` updated under `[Unreleased]` if the change is user-visible
- [ ] Comment-based help updated for any new or changed public function
- [ ] No real directory data (real DNs, SIDs, hostnames, principal names) in code, tests, or examples
- [ ] Branch is short-lived and will be deleted after merge (per CONTRIBUTING.md)
