# AD Permissions Analyzer — Implementation Plan

**Target:** PowerShell 7+ script to produce a 100% comprehensive inventory of every DACL ACE on every object in a single Active Directory domain, across all naming contexts, for least-privilege analysis.

**Consumer:** This document is consumed by Claude Code as the implementation specification. House style (`foreach`, `.Where({})`, typed collections, `CmdletBinding`, structured JSONL logging, no `Set-StrictMode`, no `ForEach-Object`/`Where-Object`) is mandatory throughout.

---

## 1. Locked-in Scope

| Decision | Value |
|---|---|
| Domain scope | Single domain (parameterized; default = current) |
| Naming contexts | All: Domain NC, Configuration NC, Schema NC, all DNS application partitions |
| ACL types | DACL only (SACL excluded) |
| Object-specific ACE decoding | Yes — resolve property, property-set, extended-right, and child-class GUIDs to human names |
| Inherited ACE handling | Capture all ACEs; flag inherited; resolve and record the source DN where the ACE was originally defined |
| Trustee group expansion | Yes — transitive expansion of group trustees to effective members |
| Orphaned/unresolvable SID handling | Categorize and emit (see §10) |
| Output | Two CSV files: per-ACE detail + per-trustee pivot |
| File splitting | Single detail file (no per-NC/per-class split) |
| Execution context | Admin workstation or utility server; online LDAP only |
| Target object count | ~30,000 objects (design ceiling) |
| Parallelism | Runspace pools only (no `ForEach-Object -Parallel`, no `Start-Job`) |
| Use case | Pure inventory snapshot |

## 2. Explicitly Out of Scope

- SACL / audit ACE enumeration
- Multi-domain / forest-wide enumeration
- Cross-forest trust traversal
- Offline `ntdsutil ifm` snapshot mode
- Risky-pattern flagging (GenericAll/WriteDacl/DCSync detection, etc.)
- Baseline diffing or anomaly detection
- Remediation actions
- GPO permission analysis (the GPO AD object's ACL is in scope; SYSVOL file ACLs are not)

These are deliberately excluded per user direction. Do not add them. If the user later requests them, they become a separate script or a feature flag — not silent additions.

---

## 3. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Phase 1: Discovery & Map Building (single-threaded)            │
│   • Bind to RootDSE, enumerate NCs                              │
│   • Build GUID → name maps (extended rights, schema)            │
│   • Build SID → principal cache (initialize, lazy-fill)         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 2: Object Enumeration (single-threaded per NC)           │
│   • Paged LDAP search per NC via S.DS.Protocols                 │
│   • Retrieve: distinguishedName, objectClass, objectGUID,       │
│     nTSecurityDescriptor (with SecurityDescriptorFlagControl)   │
│   • Batch into work units of N objects (default 250)            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 3: ACE Parsing (runspace pool, parallel)                 │
│   • Parse nTSecurityDescriptor → ActiveDirectorySecurity        │
│   • For each ACE: extract, decode, resolve GUIDs                │
│   • Emit raw ACE records                                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 4: Trustee Resolution & Group Expansion (single-threaded)│
│   • Resolve all distinct trustee SIDs                           │
│   • Transitively expand groups → effective members              │
│   • Categorize orphans                                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 5: Inheritance Source Resolution (single-threaded)       │
│   • For each inherited ACE, walk parent chain                   │
│   • Match against explicit ACEs collected in Phase 3            │
│   • Record InheritanceSourceDN                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 6: Output (streaming)                                    │
│   • Write detail CSV (one row per ACE × effective trustee)      │
│   • Write pivot CSV (one row per trustee, aggregated)           │
└─────────────────────────────────────────────────────────────────┘
```

**Why this order:** Maps must exist before ACE decoding. Trustee/inheritance resolution needs the full ACE set to be complete (e.g., to find the explicit parent ACE for an inherited child ACE). Output is last, written via streaming `StreamWriter` to avoid pinning the whole result set in memory.

---

## 4. Script Parameters

```
Invoke-ADPermissionAnalysis
    -Domain               <string>   # FQDN; default: current user's domain
    -Server               <string>   # Specific DC; default: locator
    -Credential           <PSCredential>  # Optional; default: current context
    -OutputDirectory      <string>   # Required
    -DetailFileName       <string>   # Default: "ADPermissions_Detail_<yyyyMMdd-HHmmss>.csv"
    -PivotFileName        <string>   # Default: "ADPermissions_Pivot_<yyyyMMdd-HHmmss>.csv"
    -LogFileName          <string>   # Default: "ADPermissions_<yyyyMMdd-HHmmss>.jsonl"
    -BatchSize            <int>      # Default: 250 objects per runspace work unit
    -ThreadCount          <int>      # Default: [Environment]::ProcessorCount
    -PageSize             <int>      # Default: 1000 (LDAP page size)
    -IncludeNamingContexts <string[]> # Default: @('Domain','Configuration','Schema','DNS')
                                       # Allow filtering for testing
    -SkipTransitiveExpansion <switch>  # Escape hatch; default off
```

All parameters: `[Parameter()]` with `[ValidateNotNullOrEmpty()]` / `[ValidateRange()]` as appropriate. Use `[CmdletBinding()]` on every function. Return objects, not text.

---

## 5. Function Decomposition

Each function lives in its own logical section with comment-based help (Synopsis, Description, Parameter, Example).

### Phase 1 — Discovery & Maps
- `Get-ADNamingContext` — returns `[List[PSObject]]` of NCs with DN, type (Domain/Config/Schema/DNS), and root DSE attributes.
- `New-ADExtendedRightsMap` — returns `[Dictionary[guid,PSObject]]` keyed by `rightsGuid`. Source: `CN=Extended-Rights,CN=Configuration,...`. Each value carries `DisplayName`, `AppliesTo` (schema GUIDs), `ValidAccesses` (mask).
- `New-ADSchemaGuidMap` — returns `[Dictionary[guid,PSObject]]` keyed by `schemaIDGUID`. Source: Schema NC. Each value carries `LdapDisplayName`, `ObjectCategory` (attributeSchema vs classSchema), `IsPropertySet`, `PropertySetMembers` (for property sets, the constituent attribute GUIDs).
- `New-WellKnownSidMap` — static `[Dictionary[string,string]]` of well-known SIDs not resolvable via `NTAccount.Translate()` reliably (S-1-5-32-* etc. usually work, but pre-populate edge cases like `S-1-3-0`/Creator Owner, `S-1-5-10`/Self, `S-1-5-9`/Enterprise DCs).

### Phase 2 — Enumeration
- `Get-ADObjectAclBatch` — paged LDAP search via `System.DirectoryServices.Protocols.LdapConnection` + `SearchRequest` + `PageResultRequestControl` + `SecurityDescriptorFlagControl(DACL)`. Yields batches of `[List[PSObject]]` (DN, ObjectClass, ObjectGUID, raw `nTSecurityDescriptor` byte[]). Implements early exit on empty result set.
  - **Why S.DS.Protocols, not the AD module:** AD module's `Get-ACL` per object = 30k LDAP roundtrips. Paged S.DS.P with `SecurityDescriptorFlagControl` retrieves SD inline with the search and is 1–2 orders of magnitude faster. Memory stays bounded via paging.

### Phase 3 — ACE Parsing (runs inside runspace pool)
- `ConvertFrom-NtSecurityDescriptor` — accepts raw `byte[]`, returns `[ActiveDirectorySecurity]` (`new-object` + `SetSecurityDescriptorBinaryForm`). DACL only.
- `ConvertFrom-AdAce` — accepts a single `ActiveDirectoryAccessRule`, returns a flat `PSObject` with: `ObjectDN`, `ObjectClass`, `ObjectGUID`, `TrusteeSid`, `AccessMask`, `AccessControlType` (Allow/Deny), `AceType` (e.g., `AccessAllowedObject`), `RightsDecoded` (e.g., `GenericAll, ReadProperty, WriteProperty`), `ObjectTypeGuid`, `ObjectTypeName` (decoded via maps), `ObjectTypeKind` (Property/PropertySet/ExtendedRight/Class/All), `InheritedObjectTypeGuid`, `InheritedObjectTypeName`, `InheritanceFlags`, `IsInherited`, `AceFlagsRaw`.
- `Invoke-AceParsingWorkUnit` — runspace work-unit body. Accepts a batch + the GUID maps (passed by reference into the runspace). Returns `[List[PSObject]]` of ACE records.

### Phase 4 — Trustee Resolution
- `Resolve-TrusteeSid` — accepts SID string. Resolution order:
  1. Cache lookup
  2. `[SecurityIdentifier]::new($sid).Translate([NTAccount])`
  3. Well-known SID map
  4. ForeignSecurityPrincipals container (`CN=ForeignSecurityPrincipals,<domainNC>`)
  5. Mark as `Orphaned`
- Returns `PSObject`: `Sid`, `Name` (DOMAIN\sam or fallback), `PrincipalType` (User/Group/Computer/ManagedServiceAccount/ForeignSecurityPrincipal/WellKnown/Orphaned/Unknown), `DistinguishedName` (when resolvable in-domain).
- `Expand-GroupTransitive` — for trustees of type Group, returns `[List[PSObject]]` of effective member principals. Use `LDAP_MATCHING_RULE_IN_CHAIN` (OID `1.2.840.113556.1.4.1941`) on `memberOf` for performance: one query per group resolves the entire transitive closure. Cache group → expanded-member-set keyed by group SID. Detect and break circular cases (the matching rule handles cycles, but cap recursion as a safety net).
- `Get-DistinctTrusteeSet` — single pass over the ACE record list to dedupe SIDs before resolving. 30k × 30 ACEs avg = ~900k ACE rows but typically <5k distinct trustees.

### Phase 5 — Inheritance Source
- `Resolve-InheritanceSource` — for each ACE where `IsInherited = $true`:
  1. Walk parent chain of `ObjectDN` upward.
  2. At each ancestor, look up explicit ACEs (already in the result set, indexed by `ObjectDN`) matching trustee SID + access mask + object-type GUID + inheritance flags consistent with propagation to current object class.
  3. The deepest matching ancestor is `InheritanceSourceDN`. If none found (rare; possible with default schema ACEs that originate at the domain root or have no explicit form), record `InheritanceSourceDN = $null` and `InheritanceSourceNote = 'SchemaDefaultOrUnresolved'`.
- Build a `[Dictionary[string,List[PSObject]]]` index of explicit ACEs keyed by DN before the resolution loop. Avoids O(n²).

### Phase 6 — Output
- `Write-DetailCsv` — opens `StreamWriter`, writes header, streams rows. One row per `(ACE × effective trustee)`. Schema in §11.
- `Write-PivotCsv` — aggregates the in-memory ACE+trustee join. One row per effective trustee. Schema in §11.

### Cross-cutting
- `Write-Log` — JSONL. Fields: `timestamp` (ISO-8601 UTC), `level`, `phase`, `event`, `message`, `data` (object). Used for milestones and errors only — no per-object spam. Emit phase-start / phase-end with counts.
- `New-RunspacePool` — wraps `[runspacefactory]::CreateRunspacePool`. `InitialSessionState` carries the GUID maps and the well-known SID map preloaded so each runspace doesn't rebuild them.
- `Invoke-RunspacePoolWork` — generic dispatcher: accepts pool + work-unit scriptblock + collection of input batches; returns aggregated results. Uses `BeginInvoke`/`EndInvoke`. Captures per-batch failures into a separate error list (does not throw — log and continue per house style).

---

## 6. Data Structures

| Structure | Type | Purpose |
|---|---|---|
| `$NamingContexts` | `List[PSObject]` | NC list from Phase 1 |
| `$ExtendedRightsMap` | `Dictionary[guid,PSObject]` | rightsGuid → name |
| `$SchemaGuidMap` | `Dictionary[guid,PSObject]` | schemaIDGUID → name |
| `$WellKnownSidMap` | `Dictionary[string,string]` | SID → friendly name |
| `$AceRecords` | `List[PSObject]` | All parsed ACEs (Phase 3 output) |
| `$AceByDn` | `Dictionary[string,List[PSObject]]` | Inheritance index |
| `$TrusteeCache` | `Dictionary[string,PSObject]` | SID → resolved principal |
| `$GroupExpansionCache` | `Dictionary[string,List[PSObject]]` | Group SID → transitive members |
| `$ErrorBag` | `List[PSObject]` | Captured errors |

Memory note: 900k ACE rows × ~400 bytes ≈ ~360 MB. Acceptable on an admin workstation. After detail CSV is written, set `$AceRecords = $null` before pivot generation if pivot can be derived from a streaming re-read; otherwise keep in memory and clean up at end with `Remove-Variable`.

---

## 7. ACE Decoding Rules

For each `ActiveDirectoryAccessRule`:

**RightsDecoded** — bitwise decompose `ActiveDirectoryRights`:
- Generic: `GenericAll`, `GenericRead`, `GenericWrite`, `GenericExecute`
- Standard: `Delete`, `ReadControl`, `WriteDacl`, `WriteOwner`, `Synchronize`, `AccessSystemSecurity`
- Object-specific: `CreateChild`, `DeleteChild`, `ListChildren`, `Self`, `ReadProperty`, `WriteProperty`, `DeleteTree`, `ListObject`, `ExtendedRight`
- Emit comma-delimited string of present flags.

**ObjectType GUID interpretation** — depends on `AceType` and `RightsDecoded`:

| Right | ObjectType GUID means |
|---|---|
| `ExtendedRight` | Extended right (look up in ExtendedRightsMap) |
| `ReadProperty` / `WriteProperty` | Single attribute or property set (look up in SchemaGuidMap; if it's a property set, also list members) |
| `CreateChild` / `DeleteChild` | Child object class (look up classSchema) |
| `Self` | Validated write (extended right namespace) |
| (none / zero GUID) | Applies to all properties / all child types |

**InheritedObjectType GUID** — only meaningful for ACEs that propagate; identifies the child class the ACE applies to when inherited (e.g., "applies to descendant `user` objects only"). Resolve same way as a class GUID.

`ObjectTypeKind` field disambiguates which lookup table produced the name.

---

## 8. GUID Map Construction Details

**ExtendedRightsMap source:**
- LDAP search: `CN=Extended-Rights,CN=Configuration,<forestDN>`
- Filter: `(objectClass=controlAccessRight)`
- Attributes: `cn`, `displayName`, `rightsGuid`, `appliesTo`, `validAccesses`
- Key: `[guid]$rightsGuid`

**SchemaGuidMap source:**
- LDAP search: `<schemaNC>`
- Filter: `(|(objectClass=attributeSchema)(objectClass=classSchema))`
- Attributes: `lDAPDisplayName`, `schemaIDGUID`, `objectClass`, `attributeSecurityGUID` (for property set membership)
- Key: `[guid][byte[]]$schemaIDGUID`
- Property sets: classSchema-derived; member attributes carry `attributeSecurityGUID` matching the property set's `schemaIDGUID`. Build reverse index.

**Page size:** 1000 for both. Both maps are bounded (~hundreds for extended rights, ~3000 for schema).

---

## 9. Inheritance Source Resolution — Algorithm

```
For each ACE where IsInherited = true:
    parent = Parent(ACE.ObjectDN)
    while parent is not null and parent is within any enumerated NC:
        candidates = AceByDn[parent]  # explicit ACEs only
        match = candidates.Where({
            $_.IsInherited -eq $false -and
            $_.TrusteeSid -eq ACE.TrusteeSid -and
            $_.AccessMask -eq ACE.AccessMask -and
            $_.ObjectTypeGuid -eq ACE.ObjectTypeGuid -and
            InheritanceFlagsPropagateTo(parent, ACE.ObjectDN, ACE.ObjectClass, $_.InheritanceFlags, $_.InheritedObjectTypeGuid)
        })
        if match.Count -gt 0:
            ACE.InheritanceSourceDN = parent
            break
        parent = Parent(parent)
    if not found:
        ACE.InheritanceSourceDN = null
        ACE.InheritanceSourceNote = 'SchemaDefaultOrUnresolved'
```

`InheritanceFlagsPropagateTo` is a helper that checks `ContainerInherit` / `ObjectInherit` / `InheritOnly` / `NoPropagateInherit` flags and the `InheritedObjectType` class filter against the descendant's class.

**Edge cases to handle:**
- ACEs originating from `defaultSecurityDescriptor` of the schema class (no explicit parent ACE exists for these — they're materialized at object creation). Mark `SchemaDefaultOrUnresolved`.
- Multiple matching ancestors (e.g., same ACE explicitly placed at two levels): record the deepest.
- ACEs on cross-NC objects (rare): stay within the originating NC.

---

## 10. Orphaned/Unresolvable SID Handling — Recommendation

Categorize every trustee into exactly one `PrincipalType`:

| Category | Detection |
|---|---|
| `User` / `Group` / `Computer` / `ManagedServiceAccount` | Resolved via in-domain LDAP lookup; `objectClass` determines type |
| `WellKnown` | Resolved via `NTAccount.Translate()` to `BUILTIN\*` or `NT AUTHORITY\*`, or matched in WellKnownSidMap |
| `ForeignSecurityPrincipal` | Found as object under `CN=ForeignSecurityPrincipals,<domainNC>` |
| `Orphaned` | All resolution paths failed; SID format valid; likely deleted account |
| `Unknown` | All resolution failed and SID itself is malformed (should never happen but handle defensively) |

Output row always contains the raw SID string regardless of category. Orphaned trustees still get a row in the detail CSV — they are exactly the kind of finding least-privilege reviews want to surface. Pivot CSV groups orphans together for visibility.

Do not throw on unresolvable SIDs. Log one structured event per distinct orphan SID at INFO level (`event: "OrphanSid"`).

---

## 11. Output Schema

### Detail CSV — `ADPermissions_Detail_<timestamp>.csv`

One row per `(target object × ACE × effective trustee)` after group expansion.

| Column | Type | Notes |
|---|---|---|
| `ObjectDN` | string | Target object DN |
| `ObjectClass` | string | Most-specific class (last value of `objectClass`) |
| `ObjectGUID` | guid | |
| `NamingContext` | string | Domain / Configuration / Schema / DNS:<partition> |
| `AceTrusteeSid` | string | Raw SID from ACE |
| `AceTrusteeName` | string | Resolved name (may be raw SID for orphans) |
| `AceTrusteePrincipalType` | string | See §10 |
| `EffectiveTrusteeSid` | string | After group expansion; equals AceTrusteeSid for non-group ACEs |
| `EffectiveTrusteeName` | string | |
| `EffectiveTrusteePrincipalType` | string | |
| `EffectiveTrusteeDN` | string | When in-domain |
| `IsThroughGroup` | bool | True if effective trustee differs from ACE trustee |
| `GroupExpansionPath` | string | Semicolon-delimited group chain (e.g., "GroupA -> NestedGroupB"); empty for direct |
| `AccessControlType` | string | Allow / Deny |
| `RightsDecoded` | string | Comma-delimited rights |
| `AccessMask` | uint32 | Raw mask for diffing |
| `ObjectTypeGuid` | guid? | |
| `ObjectTypeName` | string | Decoded |
| `ObjectTypeKind` | string | Property / PropertySet / ExtendedRight / ClassChild / All |
| `InheritedObjectTypeGuid` | guid? | |
| `InheritedObjectTypeName` | string | |
| `IsInherited` | bool | |
| `InheritanceSourceDN` | string | Empty for explicit; populated for inherited |
| `InheritanceSourceNote` | string | E.g., "SchemaDefaultOrUnresolved" |
| `InheritanceFlags` | string | ContainerInherit / ObjectInherit / etc. |
| `AceFlagsRaw` | byte | Raw byte for forensics |
| `CollectedAt` | datetime | UTC ISO-8601 |

### Pivot CSV — `ADPermissions_Pivot_<timestamp>.csv`

One row per effective trustee.

| Column | Type | Notes |
|---|---|---|
| `EffectiveTrusteeSid` | string | |
| `EffectiveTrusteeName` | string | |
| `EffectiveTrusteePrincipalType` | string | |
| `EffectiveTrusteeDN` | string | |
| `TotalAceCount` | int | All ACEs across all objects |
| `DirectAceCount` | int | Where `IsThroughGroup = false` |
| `IndirectAceCount` | int | Where `IsThroughGroup = true` |
| `DistinctObjectCount` | int | Distinct ObjectDNs touched |
| `AllowAceCount` | int | |
| `DenyAceCount` | int | |
| `ExplicitAceCount` | int | |
| `InheritedAceCount` | int | |
| `RightsSummary` | string | Top rights aggregated, e.g., "GenericAll:42; WriteProperty:118; ReadProperty:980" |
| `NamingContextsTouched` | string | Semicolon-delimited |
| `ObjectClassesTouched` | string | Semicolon-delimited with counts, e.g., "user:14; group:3; organizationalUnit:1" |
| `CollectedAt` | datetime | |

CSV writing: `Export-Csv` is fine for small data, but for the detail file (potentially ~1M rows) use `StreamWriter` with manual CSV escaping (RFC 4180: quote fields containing `,`, `"`, or newline; double internal quotes). Avoid pipeline overhead.

---

## 12. Performance & Parallelism

**Sizing target:** 30,000 objects, ~30 ACEs/object average → ~900,000 raw ACE rows pre-expansion. Group expansion may multiply detail rows 2–10x for ACEs assigned to large groups; design for ~5M detail rows worst case.

**Sequential phases** (single-threaded by design):
- Phase 1 (maps): trivial cost
- Phase 2 enumeration: bound by LDAP server throughput; paged search is inherently sequential per NC
- Phase 4 (trustee resolution): single-threaded with cache; resolution is fast (< few seconds)
- Phase 5 (inheritance): single-threaded but uses pre-built index → O(n × depth)

**Parallel phase** (runspace pool):
- Phase 3 ACE parsing. Work units = batches of 250 objects. Pool size = `[Environment]::ProcessorCount`.
- Each runspace receives the GUID maps via `InitialSessionState.Variables` so they aren't rebuilt or marshalled per batch.
- Each runspace returns a `List[PSObject]` of ACE records; main thread aggregates into `$AceRecords`.

**Runspace pool pattern (sketch):**
```
$iss = [InitialSessionState]::CreateDefault()
$iss.Variables.Add( [SessionStateVariableEntry]::new('ExtendedRightsMap', $extendedRightsMap, '') )
$iss.Variables.Add( [SessionStateVariableEntry]::new('SchemaGuidMap', $schemaGuidMap, '') )
$pool = [runspacefactory]::CreateRunspacePool(1, $ThreadCount, $iss, $Host)
$pool.Open()
# Submit batches via BeginInvoke; collect via EndInvoke; dispose handles
$pool.Close(); $pool.Dispose()
```

**Memory hygiene:**
- Set large temporaries to `$null` between phases (`$batches = $null` after Phase 3 completes).
- `Remove-Variable` for the GUID maps and caches at end of script.
- Stream the detail CSV — never build it as a single in-memory string.

**Early exits:** If any NC returns zero objects, log and skip. If the GUID maps are empty (corrupt schema or insufficient rights), throw — this is unrecoverable per house style.

---

## 13. Logging (JSONL)

Compatible with existing `Write-Log` / Write-Log JSONL convention. One event per line. Required fields: `timestamp`, `level`, `phase`, `event`, `message`. Optional: `data` (nested object), `correlationId`.

**Events to emit (and only these — no per-object logging):**
- `ScriptStart` (params summary)
- `PhaseStart` / `PhaseEnd` for each of the 6 phases (with counts and elapsed ms in `data`)
- `NamingContextDiscovered` (one per NC)
- `MapBuilt` (extended rights count, schema GUID count)
- `EnumerationProgress` (every N batches, e.g., every 5000 objects)
- `OrphanSid` (one per distinct orphan)
- `BatchError` (per-batch parse failures from runspaces)
- `ScriptEnd` (totals, elapsed, output paths)

Levels: `INFO`, `WARN`, `ERROR`. No `DEBUG` chatter at default verbosity.

---

## 14. Error Handling

Per house style: throw only on unrecoverable, otherwise capture/log/continue.

| Condition | Action |
|---|---|
| LDAP bind failure | Throw |
| Cannot read RootDSE | Throw |
| Schema or Extended-Rights query returns 0 | Throw |
| Single object enumeration error | Log `BatchError`, skip object, continue |
| ACE parse failure on a specific object | Log, emit a placeholder ACE record with `RightsDecoded = "PARSE_ERROR"` and the raw byte length, continue |
| SID resolution failure | Categorize as `Orphaned`, no error |
| Group expansion failure on a specific group | Log `WARN`, fall back to direct trustee only, continue |
| Inheritance source not found | `InheritanceSourceNote = "SchemaDefaultOrUnresolved"`, no error |
| CSV write failure | Throw (unrecoverable — output is the deliverable) |

All caught errors append to `$ErrorBag`. Final `ScriptEnd` log event includes `errorCount`.

---

## 15. Dependencies

**Required:**
- PowerShell 7+
- .NET assemblies (built-in): `System.DirectoryServices`, `System.DirectoryServices.Protocols`, `System.Security.Principal`
- Network reachability to a writable DC for the target domain

**Optional / not used:**
- `ActiveDirectory` PowerShell module — **not required**. The script uses S.DS.P directly for performance and to avoid the module's per-call overhead. If a function genuinely benefits from it (e.g., a fallback `Get-ADObject` for niche resolution), gate behind a capability check — do not hard-require.

**Permissions needed by the executing principal:**
- Read access to all enumerated NCs (Domain, Configuration, Schema, DNS partitions)
- Read access to `nTSecurityDescriptor` attribute on all objects (this is the non-trivial requirement — typically requires Domain Admins or an explicitly delegated principal). Document this prominently in script help.

---

## 16. Open Questions / Decisions Deferred

These were not raised during planning. Implementation may proceed with the noted defaults, but flag them at the top of the script header so future maintainers see them.

1. **ACE deduplication for identical inherited ACEs from the same source** — when two parent containers contribute the same logical ACE to a descendant (rare but possible with explicit ACE replication), do we emit two rows or one with merged source DNs? **Default:** emit one row per logical ACE, with `InheritanceSourceDN` set to the deepest match.
2. **Deny ACE precedence** — the report includes both Allow and Deny ACEs but does not compute *effective* access (which would require resolving Allow/Deny conflicts per Windows access-check semantics). Inventory only.
3. **"Domain Users" / "Authenticated Users" expansion** — these resolve to enormous implicit member sets. **Default:** do not transitively expand these well-known groups; treat as terminal trustees and flag with `EffectiveTrusteeName = AceTrusteeName`. Configurable via a future flag if needed; for now, hard-coded skip list documented in help.
4. **Tombstoned object handling** — deleted-objects container is *not* enumerated by default. Confirm this is desired.

---

## 17. Validation / Smoke Tests

Not full Pester coverage (out of scope per "pure inventory snapshot"), but the implementation should include at minimum:

1. Run against a small lab OU with known ACEs (e.g., grant `Test-User` `WriteProperty` on a specific OU) and verify the row appears in detail CSV with correct decoding.
2. Verify a known nested-group ACE expands correctly (e.g., `Tier0-Admins` granted `GenericAll`, with `Helpdesk-Admins` nested inside).
3. Verify an inherited default schema ACE (e.g., on a fresh user object) is captured with `IsInherited = true` and either a resolved `InheritanceSourceDN` or `SchemaDefaultOrUnresolved`.
4. Verify pivot row counts reconcile with detail row aggregates.
5. Run on a 30k-object domain and confirm completion within an acceptable window (target: < 30 minutes on an 8-core admin workstation; not a hard SLA).

---

## 18. Implementation Order for Claude Code

Build in this sequence so each phase is independently testable:

1. Parameters + script skeleton + `Write-Log`
2. Phase 1: NC discovery + GUID maps (testable standalone)
3. Phase 2: Enumeration (testable: count objects per NC)
4. Phase 3: ACE parsing — first single-threaded, then wrap in runspace pool
5. Phase 4: Trustee resolution + group expansion (testable: known group SID → expected member list)
6. Phase 5: Inheritance source resolution
7. Phase 6: Detail CSV writer (streaming)
8. Phase 6: Pivot CSV writer
9. End-to-end smoke run on lab domain
10. Performance pass (only if needed) on 30k-object domain

Do not skip ahead. Each phase commits independently.
