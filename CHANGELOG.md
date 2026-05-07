# Changelog

All notable changes to ADPermissionsAnalyzer are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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

### Changed

- `Invoke-PagedLdapSearch` is now a materialising thin wrapper over a new
  streaming `Read-LdapEntry` primitive that supports `-AdditionalControls`.
  Phase 1 callers and their test mocks are unchanged.

### Fixed
