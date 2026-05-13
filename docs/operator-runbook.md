# Operator Runbook — First Work-Environment Run

**Target version:** v0.2.0
**Last updated:** 2026-05-12

Self-contained checklist for running AD Permissions Analyzer against a real directory for the first time. Treat each phase as a checkpoint — don't skip ahead until the prior phase passes. Per ADR-025, v0.1.0/v0.2.0 shipped without live-LDAP smoke validation, so this run is the operational smoke test.

## Phase 0 — Pack-up (do this before transfer)

- [ ] Confirm the `v0.2.0` tag is locally checked out:
  ```powershell
  git fetch --tags origin
  git checkout v0.2.0
  git describe --tags --exact-match    # should print: v0.2.0
  ```
- [ ] Verify the local tree is clean (no uncommitted edits will sneak into the transfer):
  ```powershell
  git status
  ```
- [ ] Decide your transfer mechanism:
  - **GitHub clone** if the work box has internet to github.com: `git clone https://github.com/chaospheremk/ADPermissionsAnalyzer.git -b v0.2.0`
  - **USB / network share**: copy the entire `code/` folder (you don't need `_meta/`, `_daily/`, `.serena/`, etc. — only the repo).
  - **Git bundle**: `git bundle create adpa-v0.2.0.bundle v0.2.0` and ship the bundle. On the work side: `git clone adpa-v0.2.0.bundle ADPermissionsAnalyzer && cd ADPermissionsAnalyzer && git checkout v0.2.0`.

## Phase 1 — Target machine prerequisites

- [ ] **OS / shell**: Windows 10+ or Windows Server 2016+. Open `pwsh` (not `powershell.exe`):
  ```powershell
  $PSVersionTable.PSVersion.Major     # must be >= 7
  ```
  If `pwsh` isn't installed, get PowerShell 7+ from `winget install Microsoft.PowerShell` or your normal software channel.
- [ ] **Identity & rights**: the running account must be able to read `nTSecurityDescriptor` on every object in every NC you'll enumerate. Domain Admin works trivially. Otherwise you need explicit delegations granting `Read Permissions` on the Domain NC root, Configuration NC root, and Schema NC root (with inheritance). The script does **not** need `SeSecurityPrivilege` (SACLs are out of scope).
- [ ] **Network**: TCP/389 (LDAP, default) or TCP/636 (LDAPS) reachable to a DC from the work box. Quick test:
  ```powershell
  Test-NetConnection -ComputerName <dc-fqdn> -Port 389
  ```
- [ ] **Repo present**: cd into the cloned/unpacked repo:
  ```powershell
  cd <path>\ADPermissionsAnalyzer
  git log --oneline -1     # should show the v0.2.0 merge commit (0d45b2b)
  ```
- [ ] **Output directory**: pick a path with **~2 GB free** for the worst case (5M rows × ~100 bytes). Local SSD is best — don't write to a network share for the first run.
  ```powershell
  $out = "C:\AdPermAudit\$(Get-Date -Format yyyyMMdd-HHmm)"
  New-Item -ItemType Directory -Path $out -Force | Out-Null
  ```

## Phase 2 — Smallest-possible smoke run (one NC, low concurrency)

This run proves the pre-flight passes, parsing works on real SDs, and the CSVs/JSONL log are well-formed. Keep parallelism low — easier to debug if anything goes wrong.

- [ ] Run against the **Domain NC only**, with conservative knobs:
  ```powershell
  $params = @{
      OutputDirectory       = $out
      IncludeNamingContexts = @('Domain')
      ThreadCount           = 4
      BatchSize             = 250
  }
  & .\scripts\Invoke-ADPermissionAnalysis.ps1 @params
  ```
  If you want to point at a specific DC, add `-Server <dc-fqdn>`. If the work box isn't joined to the target domain, also add `-Domain <fqdn>` and `-Credential (Get-Credential)`.
- [ ] **Watch the exit code**: `$LASTEXITCODE` after it returns.
  - `0` = success, zero anomalies
  - `2` = success-with-warnings (`BatchError` / `InheritedAceOnProtectedDacl` events recorded; data still valid)
  - `1` = unrecoverable fault — read the JSONL log and the console error
- [ ] **Three files exist in `$out`**:
  ```powershell
  Get-ChildItem $out | Select-Object Name, Length, LastWriteTime
  ```
  You should see `ADPermissions_Detail_<ts>.csv`, `ADPermissions_Pivot_<ts>.csv`, `ADPermissions_<ts>.jsonl`.
- [ ] **Pre-flight passed** (mandatory):
  ```powershell
  Select-String -Path $out\*.jsonl -Pattern '"EventName":"PreFlightFailed"'
  # should return nothing — if anything matches, stop
  ```
- [ ] **CSVs round-trip cleanly**:
  ```powershell
  $detail = Import-Csv (Get-ChildItem $out\ADPermissions_Detail_*.csv).FullName
  $pivot  = Import-Csv (Get-ChildItem $out\ADPermissions_Pivot_*.csv).FullName
  $detail.Count        # > 0
  $pivot.Count         # > 0
  $detail[0]           # eyeball a row — DN/trustee names should look real
  ```
- [ ] **Reconciliation** (the single most important sanity check):
  ```powershell
  $detail.Count
  ($pivot | Measure-Object -Property TotalAceCount -Sum).Sum
  # these two numbers MUST be equal
  ```
- [ ] **No silent all-error result**: the detail CSV should contain mostly real rows, not PARSE_ERROR placeholders.
  ```powershell
  $detail.Where({ $_.AceType -eq 'PARSE_ERROR' }).Count
  # should be 0 or a tiny fraction of total rows
  ```

If all six checks pass — Phase 2 done.

## Phase 3 — Add Configuration + Schema NCs

This expands to the most diagnostically interesting territory: property-set GUIDs, schema-default ACEs, and the inheritance trace through partition-level objects. Untested against real schema until now.

- [ ] Re-run with three NCs:
  ```powershell
  $out = "C:\AdPermAudit\$(Get-Date -Format yyyyMMdd-HHmm)"
  New-Item -ItemType Directory -Path $out -Force | Out-Null
  $params = @{
      OutputDirectory       = $out
      IncludeNamingContexts = @('Domain', 'Configuration', 'Schema')
      ThreadCount           = 8
  }
  & .\scripts\Invoke-ADPermissionAnalysis.ps1 @params
  ```
- [ ] **Watch the JSONL log live in another pane** (recommended):
  ```powershell
  Get-Content (Get-ChildItem $out\*.jsonl).FullName -Wait -Tail 50
  ```
  Phases appear in order: `Phase1/PhaseStart` → `NamingContextDiscovered` (×4) → `MapBuilt` → `Phase1/PhaseEnd` → `Phase2/PhaseStart` → enumeration progress every ~5000 objects → ... → `Phase6/PivotEnd` → `ScriptEnd`.
- [ ] **Re-run the same six checks from Phase 2** on the new output.
- [ ] **Look for new event types that didn't appear in Phase 2** — these are the schema-NC ones the unit tests couldn't cover:
  ```powershell
  $log = Get-Content (Get-ChildItem $out\*.jsonl).FullName | ConvertFrom-Json
  $log | Group-Object EventName | Sort-Object Count -Descending | Select-Object Count, Name
  ```
  Expected event names: `ScriptStart`, `PhaseStart`, `PhaseEnd`, `NamingContextDiscovered`, `MapBuilt`, `EnumerationProgress`, `NamingContextComplete`, `Phase6Progress`, `PivotStart`, `PivotEnd`, `ScriptEnd`. Anything unexpected — see the decoder ring below.

## Phase 4 — Full enumeration (all NCs, production concurrency)

- [ ] Final run, all NCs:
  ```powershell
  $out = "C:\AdPermAudit\$(Get-Date -Format yyyyMMdd-HHmm)"
  New-Item -ItemType Directory -Path $out -Force | Out-Null
  & .\scripts\Invoke-ADPermissionAnalysis.ps1 -OutputDirectory $out
  ```
  Default `-IncludeNamingContexts` is Domain + Configuration + Schema + DNS; default `-ThreadCount` is `[Environment]::ProcessorCount`. If your work box has 32 cores, consider `-ThreadCount 16` — values above 16 typically don't pay off because the DC becomes the bottleneck.
- [ ] **Note the wall-clock time** (the `ScriptEnd` event's `elapsedMs` field) and **object count** (`Phase2/PhaseEnd`'s `totalObjects`). Useful baseline if you re-run later.
- [ ] **Same six checks again**.
- [ ] **Per-NC sanity check** — every NC you asked for should appear in the log:
  ```powershell
  $log = Get-Content (Get-ChildItem $out\*.jsonl).FullName | ConvertFrom-Json
  $log.Where({ $_.EventName -eq 'NamingContextComplete' }) |
      Select-Object @{N='NC';E={$_.data.namingContext}}, @{N='Count';E={$_.data.objectCount}}, @{N='ms';E={$_.data.elapsedMs}}
  ```
  Each NC should have `objectCount > 0`. If you see `EmptyNamingContext` events, that NC really was empty (rare but legit for some app partitions) — not a bug.

## Phase 5 — Read the output

- [ ] **Pivot CSV is for humans**. Has a UTF-8 BOM — opens cleanly in Excel on Windows including non-ASCII names. Each row = one effective trustee with their aggregated rights, object counts, and the NCs they touch.
- [ ] **Detail CSV is for tooling**. BOM-less UTF-8 for pandas / Power BI / SIEM. If you must open in Excel, use Data → From Text/CSV → UTF-8 (not double-click).
- [ ] **Top-trustees quick look**:
  ```powershell
  $pivot | Sort-Object { [int] $_.TotalAceCount } -Descending |
      Select-Object EffectiveTrusteeName, EffectiveTrusteePrincipalType, TotalAceCount, DistinctObjectCount, RightsSummary -First 25
  ```
- [ ] **Spot any `PrincipalType = Orphaned` trustees** — these are unresolvable SIDs (deleted accounts that still have ACEs). The pivot row's `EffectiveTrusteeName` will be the raw SID:
  ```powershell
  $pivot.Where({ $_.EffectiveTrusteePrincipalType -eq 'Orphaned' }) |
      Select-Object EffectiveTrusteeSid, TotalAceCount
  ```
- [ ] **Spot any `PrincipalType = CrossDomain`** — trusted-forest/external principals (new in v0.2.0). Confirm those make sense for your environment:
  ```powershell
  $pivot.Where({ $_.EffectiveTrusteePrincipalType -eq 'CrossDomain' }) |
      Select-Object EffectiveTrusteeName, EffectiveTrusteeSid, TotalAceCount
  ```

## Phase 6 — Output handling and disposal

- [ ] **Sensitivity**: the CSVs and JSONL log all contain real SIDs, DNs, trustee names, and structural directory information. Treat as `Confidential` (or your org's equivalent). Don't paste into pastebins / chat tools / external trackers without scrubbing.
- [ ] If you need to share findings, **redact** SIDs / DNs first or share aggregates only.
- [ ] Archive runs you want to keep (compress + move to a controlled location); delete temp runs.

---

## JSONL event decoder ring

| Event | Phase | Meaning | What to do |
|---|---|---|---|
| `ScriptStart` / `ScriptEnd` | wrapper | Run boundaries | None |
| `PreFlightFailed` | PreFlight | **STOP** — script aborted before Phase 2 | Check `data.reason`: `NullOrEmptySecurityDescriptor` = account lacks DACL read; `NoNamingContextsMatched` = typo in `-IncludeNamingContexts` |
| `NamingContextDiscovered` | Phase 1 | One NC found in RootDSE | None — informational |
| `MapBuilt` | Phase 1 | GUID/SID maps built | Check `data.extendedRights` and `data.schemaGuids` > 0 |
| `EnumerationProgress` | Phase 2 | Every ~5000 objects in an NC | Heartbeat — confirms forward progress |
| `NamingContextComplete` | Phase 2 | One NC fully enumerated | None |
| `EmptyNamingContext` | Phase 2 | NC returned zero objects | Investigate if surprising — usually a legit empty app partition |
| `BatchError` | Phase 3 | One runspace batch threw | Inspect `data.namingContext` + `data.batchSize` and the message. Non-fatal; ACEs in that batch were lost. Run completes with exit 2 |
| `InheritedAceOnProtectedDacl` | Phase 5 | Inherited ACE on `IsDaclProtected=true` object — internally inconsistent SD (rare) | Inspect `data.objectDN`. Non-fatal; logged for investigation. Exit code 2 |
| `Phase6Progress` | Phase 6 | Every 50,000 detail rows written | Heartbeat |
| `PivotStart` / `PivotEnd` | Phase 6 | Pivot CSV phase boundaries | Check `PivotEnd.data.pivotRowCount` |

If you see a **Write-Warning** in the console about `transitive expansion truncated at -MaxMembers=...`, a group's transitive closure exceeded the default 100,000-member cap. The detail CSV is incomplete for that group only. In v0.2.0 the cap is fixed at the default; raising it would require a code change.

---

## Common failure modes

**Pre-flight `NullOrEmptySecurityDescriptor`** — your account can't read DACLs on the Domain NC root. Either run as Domain Admin or delegate `Read Permissions` (with inheritance) on the Domain NC root, Config NC root, and Schema NC root to your account.

**Pre-flight `NoNamingContextsMatched`** — you typo'd `-IncludeNamingContexts`. Valid values: `Domain`, `Configuration`, `Schema`, `DNS`, `Other`.

**`LdapException: The LDAP server is unavailable`** at script start — wrong `-Server`, wrong `-Domain`, or firewall. Verify with `Test-NetConnection -ComputerName <dc> -Port 389`.

**Lots of `BatchError` events** — usually a DC-side timeout under load. Re-run with `-ThreadCount 4` to reduce concurrent pressure. If it persists on light load, capture one error message and investigate.

**`PARSE_ERROR` dominates the detail CSV** — almost always an SD-read permission gap that the pre-flight missed (e.g., the Domain NC root is readable but specific OUs aren't). The `ObjectTypeName` column on PARSE_ERROR rows carries the underlying exception text; group by it to triage:
```powershell
$detail.Where({ $_.AceType -eq 'PARSE_ERROR' }) |
    Group-Object ObjectTypeName |
    Sort-Object Count -Descending |
    Select-Object Count, Name
```

**Pivot `TotalAceCount` sum ≠ detail row count** — internal inconsistency, file an issue. Capture the JSONL log and both CSVs.

**Run takes way longer than expected** — first thing to check: the `EnumerationProgress` events' interval. If they're stalling, the DC is throttling or the network is slow. Second: large groups triggering deep transitive expansion. Check `Phase4/PhaseEnd.data.expandedGroups` and `expansionCacheHitRatio` — a low hit ratio with many expansions means lots of LDAP work.

---

## Aborting mid-run

`Ctrl+C` is safe. The script writes the JSONL log incrementally (`AutoFlush=$false`; on exit it flushes via `finally`). The detail CSV's last buffer of rows (~4 KB) may be lost but everything before is on disk. The pivot CSV is written at the end and won't exist if you abort during phases 1–5.

## Re-running safely

Each run writes to its own timestamped filename inside `-OutputDirectory`, so re-runs never collide. The script is fully read-only against AD — no replication impact, no audit-relevant changes. You can re-run as many times as you like. Off-hours is courteous on a busy production directory but not required.
