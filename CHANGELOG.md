# Changelog

All notable changes to ADPermissionsAnalyzer are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.0] - 2026-05-11

v0.1.0 hardening release. Driven by a fresh-context code review run between v0.1.0 and the first work-environment test. Closes out correctness, security, performance, ergonomics, and test-coverage findings before the first live-LDAP run. Coverage moves from 91.22% to 93.22% (gated at 86% per ADR-026).

### Added

- **Pre-flight checks** (ADR-027). Two guards inserted between Phase 1 and Phase 2 in `scripts/Invoke-ADPermissionAnalysis.ps1` (`PreFlightFailed` ERROR events with `reason = NullOrEmptySecurityDescriptor` / `NoNamingContextsMatched`):
  - **`nTSecurityDescriptor` readability probe**: a single Base-scope read on the Domain NC root with `SecurityDescriptorFlagControl(Owner | Dacl)`. Aborts before Phase 2 if the running account cannot read DACLs, eliminating the v0.1.0 "silent false success" risk where an under-privileged run produced zero-row CSVs with exit code 0.
  - **`-IncludeNamingContexts` non-empty validation**: aborts on a typo or empty match (data block includes both requested and discovered NC types for diagnosis).
- **`Submit-RunspaceWorkItem` + `Receive-RunspaceHandle`** (`scripts/lib/Phase3-AceParsing.ps1`). Split out from `Invoke-RunspacePoolWork` so the orchestrator can dispatch Phase 2 batches into the runspace pool the moment they arrive (plan §12 interleaved pipeline), then drain at the end. Removes the inline `BeginInvoke`/`EndInvoke` loop from the entry script. `Receive-RunspaceHandle` also captures non-terminating `Streams.Error` records on each pipeline (previously dropped).
- **CrossDomain trustee classification** (`scripts/lib/Phase4-TrusteeResolution.ps1`). New `PrincipalType` value for trustees whose SID translates via LSA but does not exist in the local directory (trusted-forest / external principals). Distinct from `WellKnown` (built-in / NT AUTHORITY) and `Orphaned` (no Translate).
- **`Expand-GroupTransitive` truncation warning** (`scripts/lib/Phase4-TrusteeResolution.ps1:608`). Emits a `Write-Warning` when the `MaxMembers` cap is hit, so operators know the expansion was incomplete (previously silent).
- **`Get-PageResultControl`** (`scripts/lib/Phase1-DiscoveryAndMaps.ps1`). Extracted from `Read-LdapEntry`'s paging loop so the cookie continuation can be unit-tested with a duck-typed fake response.
- **Tests** (`Tests/Phase{1,3,4,5,6}-*.Tests.ps1`): six new unit cases.
  - Phase 3 — `Invoke-AceParsingWorkUnit` against a row with `NTSecurityDescriptor = $null` emits a `PARSE_ERROR` placeholder.
  - Phase 1 — `Read-LdapEntry` paging continuation across two pages (mocked `Get-PageResultControl`).
  - Phase 4 — `Expand-GroupTransitive` caps at `-MaxMembers` and emits the warning.
  - Phase 4 — `Resolve-TrusteeSid` classifies CrossDomain.
  - Phase 5 — `Resolve-InheritanceSource` parent walk stops at the Configuration NC root and does not cross into the Domain NC.
  - Phase 6 — `Write-DetailCsv` `ProgressCallback` fires every `-ProgressInterval` rows with the expected counter.

### Changed

- **Phase 6 row-build inlined** (ADR-028). `ConvertTo-DetailRow` deleted; its body moved directly into `Write-DetailCsv`'s `foreach ($tuple in $tuples)` loop with per-ACE caching of invariant fields and a reused `[string[]]` row buffer. Removes the per-row hashtable + values-array + escaped-array allocation triple at the ~5M-row design ceiling. `New-CsvFieldEscaper` is retained exactly per ADR-019. Phase 6 tests reworked to drive `Write-DetailCsv` end-to-end via `Import-Csv`.
- **Pivot CSV ships with UTF-8 BOM** (ADR-018 amended). `scripts/lib/Phase6-Output.ps1:914` switched to `[UTF8Encoding]::new($true)` so Excel on Windows renders non-ASCII DNs and trustee names correctly without a manual import step. Detail CSV remains BOM-less for batch consumers (Power BI, pandas, SIEM).
- **Phase 5 anomaly EventName renamed** (ADR-016 amended). `InheritedAceOnProtectedDacl` log events use `EventName = 'InheritedAceOnProtectedDacl'` (was `'BatchError'`) so they're distinct from Phase 3 runspace-batch failures in log analysis. The `reason` data field is preserved for back-compat.
- **`Invoke-RunspacePoolWork`** now delegates internally to `Submit-RunspaceWorkItem` + `Receive-RunspaceHandle`. Public signature unchanged; existing tests pass without modification.
- **Phase 3 inline drain replaced** with `Receive-RunspaceHandle` call in `scripts/Invoke-ADPermissionAnalysis.ps1`. The orchestrator iterates new ErrorBag entries post-drain to fan them out to `Write-LogEvent` with Phase 3 metadata.
- **Test style** — three lingering `ForEach-Object` invocations replaced with `.ForEach({})` or pipe form (`Tests/Phase3-*.ps1`, `Tests/Phase4-*.ps1`).
- **`Read-LdapEntry`** drops its `[SearchResponse]` cast on the response from `SendRequest` so duck-typed fakes work; production type narrowing is now implicit in the property access pattern.

### Fixed

- **Domain SID removed from Phase 4 PhaseEnd log event** (`scripts/Invoke-ADPermissionAnalysis.ps1`). The JSONL log no longer carries a real domain identifier — closes a `_meta/security.md` policy violation surfaced by the v0.1.0 review.
- **`[int]` → `[long]` elapsed-ms casts** (9 sites across orchestrator + `Phase6-Output.ps1`). Prevents negative elapsed-time values in JSONL logs for phases running longer than ~24 days (the `[int32]` rollover boundary in milliseconds).
- **`$script:LogWriter.AutoFlush = $false`** (`scripts/Invoke-ADPermissionAnalysis.ps1:251`). Removes per-event syscall cost on slow storage; the finally block already flushes + disposes on exit.
- **`ThreadCount` doc / range alignment** (`scripts/Invoke-ADPermissionAnalysis.ps1:58-59`). Docstring now explicitly states the 1-32 accepted range alongside the practical 8-16 sweet spot.



First release. Implements the six-phase orchestration from plan §18 steps 1–8 (steps 9–10 cancelled by ADR-025: no lab DC available). Ships without live-LDAP smoke validation; first operational run is exploratory. Correctness rests on 144 Pester unit cases across `scripts/lib/` (91.22% command coverage, gated at 86% per ADR-026).

### Added

- `scripts/Invoke-ADPermissionAnalysis.ps1` — entry-point script skeleton (plan
  §18.1): full parameter surface, JSONL logging primitive (`Write-LogEvent`),
  and top-level execution flow with deterministic exit codes (0 / 1 / 2). Phase
  bodies are stubbed pending §18.2-§18.8.
- `scripts/lib/Phase1-DiscoveryAndMaps.ps1` — Phase 1 helpers (plan §18.2):
  `Connect-AdLdap`, `Read-LdapEntry`, `Invoke-PagedLdapSearch`,
  `Get-NamingContextType`, `Get-ADNamingContext`, `New-ADExtendedRightsMap`,
  `New-ADSchemaGuidMap`, `New-PropertySetMembersMap`, `New-WellKnownSidMap`.
  Dot-sourced from the entry script.
- Phase 1 wired into `Invoke-ADPermissionAnalysis.ps1`: binds an
  `LdapConnection`, enumerates naming contexts, and builds the four maps,
  emitting `PhaseStart`, `NamingContextDiscovered`, `MapBuilt`, and `PhaseEnd`
  events (plan §13).
- `Tests/Phase1-DiscoveryAndMaps.Tests.ps1` — Pester suite (21 cases) covering
  the well-known SID map, NC categorisation, and the three LDAP-backed map
  builders mocked at the `Invoke-PagedLdapSearch` boundary.
- `scripts/lib/Phase2-Enumeration.ps1` — Phase 2 helper (plan §18.3):
  `Get-ADObjectAclBatch` performs a paged subtree search with
  `SecurityDescriptorFlagControl(OWNER | DACL)` attached, yielding
  `[List[PSObject]]` batches of `(DistinguishedName, StructuralObjectClass,
  ObjectGUID, NTSecurityDescriptor)` for downstream Phase 3 consumption.
  `structuralObjectClass` falls back to the last `objectClass` value when
  unset.
- Phase 2 wired into `Invoke-ADPermissionAnalysis.ps1`: filters
  `$namingContexts` by `-IncludeNamingContexts`, iterates batches per NC,
  emits `PhaseStart` / `EnumerationProgress` (every ~5000 objects) /
  `NamingContextComplete` / `EmptyNamingContext` / `PhaseEnd` events plus
  `Write-Progress` ticks.
- `Tests/Phase2-Enumeration.Tests.ps1` — Pester suite (12 unit cases plus one
  skipped integration case gated on `$env:AD_PERM_ANALYZER_INTEGRATION`)
  covering empty-NC short-circuit, batching invariants, attribute extraction
  (`byte[]` SD passthrough, GUID conversion, structuralObjectClass fallback,
  DN preservation), and LDAP request shape (control mask, binary attributes,
  scope/filter).
- `scripts/lib/Phase3-AceParsing.ps1` — Phase 3 helpers (plan §18.4):
  `ConvertFrom-NtSecurityDescriptor` (Owner + DACL + IsDaclProtected from
  `ActiveDirectorySecurity.AreAccessRulesProtected`), `Add-OwnerAce` (synthetic
  Owner row with `AceIndex = -1`, `RightsDecoded = 'OwnerImplicit'`,
  `AccessMask = 0xE0000`), `ConvertFrom-AdAce` (rights ToString comma-decompose,
  ObjectTypeKind classifier across the three GUID maps per plan §7,
  AceFlagsRaw composition from inheritance + propagation + IsInherited),
  `Invoke-AceParsingWorkUnit` (per-object SD parse with `AceIndex = -2`
  PARSE_ERROR placeholder isolation), `New-RunspacePool`
  (`InitialSessionState` carries GUID maps via `SessionStateVariableEntry`
  + lib file via `iss.StartupScripts`), `Invoke-RunspacePoolWork` (dispatcher
  with per-batch `BatchError` capture into `-ErrorBag`).
- Phase 3 wired into `Invoke-ADPermissionAnalysis.ps1`: pool created before
  Phase 2 enumeration, batches dispatched as they arrive (pipelined
  enumeration + parsing per plan §12), drained after `Phase2EndPhaseEnd`
  emits, BatchError logged via `Write-LogEvent` and aggregated into
  `$script:ErrorBag`. `Phase3PhaseStart` / `PhaseEnd` events carry batch
  count + ACE total (plan §13).
- `Tests/Phase3-AceParsing.Tests.ps1` — Pester suite (32 cases) covering
  Owner parsing, IsDaclProtected detection (set + unset), synthetic Owner ACE
  shape, GenericAll comma-decomposed RightsDecoded, all five ObjectTypeKind
  classifications (Property / PropertySet / ExtendedRight / ClassChild /
  All / Unresolved), AceType naming
  (AccessAllowed/AccessDenied/AccessAllowedObject/AccessDeniedObject),
  AceIndex preservation, AceFlagsRaw composition, IsDaclProtected
  propagation, work-unit owner+DACL emission, PARSE_ERROR placeholder
  isolation, runspace pool aggregation, BatchError capture, variable
  injection, and StartupScripts dot-source.
- `scripts/lib/Phase4-TrusteeResolution.ps1` — Phase 4 helpers (plan §18.5):
  `Resolve-NTAccount` (mockable wrapper around `[SecurityIdentifier].Translate`),
  `ConvertTo-LdapBinaryFilter` (escapes a SID into the `\xx\xx` form an
  `objectSid` filter expects), `Get-PrincipalTypeFromObjectClass` (pure
  classifier with `msDS-GroupManagedServiceAccount` / `msDS-ManagedServiceAccount`
  / `computer` / `group` / `user` priority — gMSA wins over its inherited
  base classes), `Get-DomainSid` (base-scope `objectSid` read on the domain NC
  root), `New-WellKnownSidSkipSet` (universal SIDs from plan §10 plus
  domain-relative RIDs `-498` / `-513` / `-514` / `-515` / `-516` / `-521`
  resolved against the runtime domain SID), `Test-IsTerminalSid`
  (HashSet lookup + `S-1-5-32-*` BUILTIN prefix match), `Get-DistinctTrusteeSet`
  (single-pass dedupe over `$aceRecords` covering DACL + Synthetic.Owner rows),
  `Resolve-DomainPrincipal`, `Resolve-ForeignSecurityPrincipal`,
  `Resolve-TrusteeSid` (cache → Translate → WellKnownSidMap → FSP → Orphaned
  per plan §5; `BUILTIN\*` and `NT AUTHORITY\*` translates short-circuit to
  `WellKnown` without an LDAP roundtrip), `Expand-GroupTransitive`
  (`(memberOf:1.2.840.113556.1.4.1941:=<groupDN>)` against the domain NC
  subtree, cached by group SID, defensive `-MaxMembers` cap default 100000).
- Phase 4 wired into `Invoke-ADPermissionAnalysis.ps1`: runs single-threaded
  after the Phase 3 drain — discovers domain SID + builds the skip set,
  dedupes trustees, resolves all distinct SIDs into `$script:TrusteeCache`,
  expands non-terminal groups with a DN into `$script:GroupExpansionCache`
  (skipped entirely under `-SkipTransitiveExpansion`), emits
  `PhaseStart` / `OrphanSid` (one per distinct orphan) / `PhaseEnd` events
  with distinct/resolved/orphan/expanded counts and group-expansion cache
  hit ratio per plan §13.
- `Tests/Phase4-TrusteeResolution.Tests.ps1` — Pester suite (28 cases)
  mocking at `Resolve-NTAccount` and `Invoke-PagedLdapSearch`. Covers
  cache short-circuit (zero LSA + zero LDAP after first hit),
  `NT AUTHORITY\SYSTEM` translate-only path, well-known SID fallback when
  Translate throws, in-domain User resolution via Translate +
  LDAP-by-objectSid, sMSA vs gMSA via objectClass priority, FSP
  classification with FSP-container search-base filter, Orphan when all
  paths fail, `Test-IsTerminalSid` against Everyone / Domain Users /
  BUILTIN aliases, `Get-DistinctTrusteeSet` dedupe across DACL +
  Synthetic.Owner rows, group transitive expansion (nested A → B →
  {user1, user2}) with cache populated, repeat-call cache short-circuit
  on `Expand-GroupTransitive`, and `Get-DomainSid` round-trip + empty-NC
  throw.

- `scripts/lib/Phase5-InheritanceSource.ps1` — Phase 5 helpers (plan §18.6):
  `New-AceIndex` (composite-key `Dictionary[ValueTuple[string, string,
  uint32, guid], List[PSObject]]` keyed by `(ObjectDN-upper, TrusteeSid,
  AccessMask, ObjectTypeGuid)` over EXPLICIT rows only; skips inherited,
  Synthetic.Owner `AceIndex = -1`, and PARSE_ERROR `AceIndex = -2`),
  `Get-ParentDistinguishedName` (char-by-char DN tokenizer respecting
  `\,` / `\\` / `\HH` LDAP escapes, returns `$null` at NC root),
  `Test-IsContainerClass` (heuristic over the small set of AD container
  classes), `Test-InheritanceFlagsPropagateTo` (pure rule over
  `AceFlagsRaw` byte + `InheritedObjectTypeName` + descendant class +
  `IsDirectChild`; encodes ContainerInherit / ObjectInherit container-vs-leaf
  gating, NoPropagateInherit level-1-only halt, InheritOnly transparent for
  descendants, InheritedObjectType class filter via OI string equality),
  `Resolve-InheritanceSource` (mutates `$aceRecords` in place — adds
  `InheritanceSourceDN` and `InheritanceSourceNote` columns on every row;
  DACL_PROTECTED short-circuits to `InconsistentProtectedDacl` and emits
  the anomaly into `-ProtectedDaclAnomalies`; otherwise walks the parent
  chain via `Get-ParentDistinguishedName`, direct-lookup at each ancestor,
  first matching candidate wins; `SchemaDefaultOrUnresolved` fallback;
  stops at NC root or beyond; returns stats record with `Indexed`,
  `InheritedTotal`, `Resolved`, `Unresolved`, `ProtectedDacl`).
- Phase 5 wired into `Invoke-ADPermissionAnalysis.ps1`: runs single-threaded
  after Phase 4 `PhaseEnd`. Builds the index, extracts NC DNs into a
  `List[string]`, calls `Resolve-InheritanceSource` with an anomaly sink,
  forwards each `InheritedAceOnProtectedDacl` anomaly to `Write-LogEvent`
  at WARN with `EventName = 'BatchError'` (matches Phase 3's BatchError
  contract from §13) AND adds it to `$script:ErrorBag` so the §14
  exit-code-2 path picks them up. `PhaseStart` / `PhaseEnd` events emit
  per plan §13 with `indexed` / `inheritedTotal` / `resolved` /
  `unresolved` / `protectedDacl` counts.
- `Tests/Phase5-InheritanceSource.Tests.ps1` — Pester suite (24 cases)
  covering `New-AceIndex` (explicit-only indexing, inherited skip,
  Synthetic.Owner / PARSE_ERROR skip, composite-key collision stacking),
  `Get-ParentDistinguishedName` (standard DN, escaped-comma RDN value,
  NC root → null, empty input → null), `Test-InheritanceFlagsPropagateTo`
  (ContainerInherit/ObjectInherit container-vs-leaf gating in both
  directions, InheritOnly transparent for descendants, NoPropagateInherit
  level-1-only halt, InheritedObjectType class filter user/group, no
  inherit flags returns false), and `Resolve-InheritanceSource`
  end-to-end (direct-parent resolution, two-level walk past failing-flag
  level-1 candidate, DACL_PROTECTED short-circuit + anomaly emission,
  `SchemaDefaultOrUnresolved` fallback, explicit rows un-mutated, and
  Synthetic.Owner / PARSE_ERROR rows still get the columns added with
  empty values for uniform Phase 6 schema).

- `scripts/lib/Phase6-Output.ps1` — Phase 6 detail-CSV writer (plan §18.7):
  `New-CsvFieldEscaper` (RFC-4180 rule — quote when value contains `,` /
  `"` / CR / LF; double internal `"`; passthrough otherwise),
  `Write-CsvHeader` (writes the 30-column header line via the supplied
  `[StreamWriter]`; column order lives in `$script:Phase6DetailColumns`,
  the single source of truth shared with `ConvertTo-DetailRow`),
  `ConvertTo-DetailRow` (pure transform: ACE record + AceTrustee +
  EffectiveTrustee + IsThroughGroup + GroupExpansionPath + NamingContext
  + CollectedAt → `[string[]]` of escaped fields in plan-§11 order),
  `Get-EffectiveTrusteeRecord` (single-pass fan-out: cache-hit non-empty
  group → one tuple per cached transitive member with `IsThroughGroup =
  $true`; otherwise direct trustee with `IsThroughGroup = $false`; cache
  miss falls back to a synthetic trustee carrying the raw SID),
  `Resolve-NamingContextLabel` (longest-suffix DN match against the NC
  list, memoised per ObjectDN — Schema NC wins over Configuration NC for
  Schema-scoped objects), `Update-PivotStat` (per-row mutation of the
  `$PivotStats` accumulator; lazy-seeds each EffectiveTrusteeSid bucket
  on first emission), `Write-DetailCsv` (orchestrator: opens
  `[StreamWriter]` UTF-8 no-BOM with `AutoFlush = $false`, header → for
  each ACE expand → write/update → flush at end; `-ProgressCallback`
  scriptblock fires every `-ProgressInterval` rows so the entry script
  forwards to `Write-LogEvent` without coupling the lib to logging).
- Phase 6 wired into `Invoke-ADPermissionAnalysis.ps1`: creates
  `$script:PivotStats` and the run's `$collectedAt` ISO-8601 stamp after
  Phase 5 `PhaseEnd`, calls `Write-DetailCsv` with a `Write-LogEvent`-
  forwarding progress callback (`Phase6Progress` every 50 000 rows plus
  `Write-Progress` ticks), then emits `PhaseEnd` with `detailRowCount`,
  `distinctTrustees`, and `elapsedMs`. `$script:PivotStats` is left in
  place for Step 8's pivot-CSV writer to consume directly with no second
  pass over `$aceRecords`.
- `Tests/Phase6-Output.Tests.ps1` — Pester suite (16 cases) covering
  `New-CsvFieldEscaper` (clean string passthrough, `$null`, comma
  trigger, embedded `"` doubles + quotes, embedded LF, embedded CR);
  `ConvertTo-DetailRow` (column count + order via 30-element
  assertions, Synthetic.Owner row passthrough with AceIndex = -1 /
  OwnerImplicit / Allow, PARSE_ERROR row preserves the captured
  exception message in ObjectTypeName, InheritanceSourceDN populated for
  inherited rows); `Get-EffectiveTrusteeRecord` (direct-trustee one-tuple
  with `IsThroughGroup = $false`, group fan-out to two cached members
  with `GroupExpansionPath` = group name, terminal-skip path emits the
  group as itself, cache-miss falls back to synthetic trustee);
  `Write-DetailCsv` end-to-end (writes header + N body lines and a
  RightsDecoded field containing comma + double-quote round-trips through
  `Import-Csv` correctly; `$PivotStats` populated with expected counters
  per trustee — TotalAceCount / Direct vs Indirect / Allow vs Deny /
  Explicit vs Inherited / DistinctObjectDns / RightsBreakdown — across a
  4-row fixture mixing direct and group-expanded trustees).

- `scripts/lib/Phase6-Output.ps1` — Phase 6 pivot CSV writer (plan §18.8):
  `$script:Phase6PivotColumns` (16-column source of truth shared by header
  + body), `Format-RightsSummary` / `Format-ObjectClassesTouched` (count
  desc, name asc tiebreak — `"GenericAll:42; WriteProperty:118;
  ReadProperty:980"` shape; empty / null dict → `''`),
  `Format-NamingContextsTouched` (sorted ordinal-ignore-case, joined with
  `;` — `"Configuration;Domain;Schema"`), `ConvertTo-PivotRow` (pure
  transform: PivotStats bucket + CollectedAt → 16 escaped fields in
  plan-§11 pivot order; `DistinctObjectCount` is the bucket's
  `DistinctObjectDns.Count`), `Write-PivotCsv` (orchestrator: opens its
  own `[StreamWriter]` UTF-8 no-BOM `AutoFlush = $false`, sorts buckets
  by TotalAceCount desc → EffectiveTrusteeName asc → SID asc, writes
  header + one row per bucket via `ConvertTo-PivotRow`, returns row
  count).
- Phase 6 pivot wired into `Invoke-ADPermissionAnalysis.ps1`: emits a
  fresh `Phase6 / PivotStart` and `Phase6 / PivotEnd` JSONL pair so the
  detail-write and pivot-write phases are distinguishable in the log;
  `PivotEnd.data` carries `pivotRowCount` + `elapsedMs`.
- `Tests/Phase6-Output.Tests.ps1` — extended Pester suite (now 31 cases)
  with: `Format-RightsSummary` (empty / `$null` → `''`, count-desc sort
  with `name-asc` tiebreak), `Format-NamingContextsTouched` (empty /
  `$null`, ordinal-ignore-case ascending join), `Format-ObjectClassesTouched`
  (sort + tiebreak), `ConvertTo-PivotRow` (16 columns in plan-§11 order;
  scalar counts plus the three formatted summaries; `DistinctObjectCount`
  derives from `DistinctObjectDns.Count`), and `Write-PivotCsv` end-to-end
  (3-bucket fixture sorted by activity desc, `Import-Csv` round-trip,
  `RightsSummary` with embedded `,` and `;` round-trips correctly, and a
  reconciliation case asserting that `sum(stats[*].TotalAceCount)` over
  the pivot equals `Write-DetailCsv`'s returned row count).

### Changed

- `Invoke-PagedLdapSearch` is now a materialising thin wrapper over a new
  streaming `Read-LdapEntry` primitive that supports `-AdditionalControls`.
  Phase 1 callers and their test mocks are unchanged.
- Phase 5 is the FIRST phase that mutates `$aceRecords` — every row gains
  `InheritanceSourceDN` (default `$null`) and `InheritanceSourceNote`
  (default `''`) note properties so the Phase 6 detail-CSV schema is
  uniform across explicit / inherited / Synthetic.Owner / PARSE_ERROR
  rows. Earlier phases were producers or pure consumers.
- Plan §17 (Validation / Smoke Tests) and §18 steps 9–10 (lab smoke run +
  30k-object performance pass) removed: no lab DC is available to this
  project, so live-LDAP validation is out of scope. The implementation
  ends at §18 step 8 (Phase 6 pivot CSV writer); correctness rests on the
  Pester unit suites attached to each phase. See ADR-025.
- `build.config.psd1`: `CoveragePaths` narrowed from `'scripts'` to
  `'scripts/lib'` and `CoverageThreshold` raised from `0` to `86`.
  Coverage now scopes to the unit-testable lib surface only — entry
  script and `Install-GitHooks.ps1` are excluded as
  integration-test / utility surface (see ADR-025 for the entry script's
  testability rationale). `86` is 5pp below the measured lib floor of
  `91.22%` per ADR-026 — high enough to lock in current coverage as a
  regression gate, low enough that a single new untested helper doesn't
  break CI.
- `scripts/Invoke-ADPermissionAnalysis.ps1` `.DESCRIPTION` rewritten to
  reflect the shipped six-phase orchestration. Previous text framed the
  script as a "skeleton entry point" with phase bodies pending §18.2-§18.8
  — true at PR #9, stale since Step 8 (PR #16). Behaviour unchanged.
- `scripts/lib/Phase6-Output.ps1` `.SYNOPSIS` / `.DESCRIPTION` and
  `Write-DetailCsv` per-function help: replaced "Step 8 will serialise" /
  "Step 8 needs no second pass" / "Step 8's Pivot CSV writer consumes
  this" with `Write-PivotCsv` references. Behaviour unchanged.
- `scripts/lib/Phase4-TrusteeResolution.ps1` `.DESCRIPTION`: dropped the
  stale "(Step 7)" parenthetical pointing at Phase 6's consumer role.
- `docs/index.md`: dropped the "(pre-refinement)" qualifier on the plan
  link — the plan was refined in PR #8 and again in PR #17.
- `Export-ScriptDocumentation.ps1` example splitter: track brace/paren
  depth and a sticky multi-line flag so multi-line splat hashtables (the
  house-style 3+ parameter idiom) round-trip correctly into the
  generated `## Examples` section. Previously the splat opener was
  treated as the only command line and every subsequent line collapsed
  into the description, producing a malformed Example 2 block on
  `Invoke-ADPermissionAnalysis.md`.
