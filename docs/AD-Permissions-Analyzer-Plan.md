# AD Permissions Analyzer — Implementation Plan

**Target:** PowerShell 7+ script to produce a 100% comprehensive inventory of every DACL ACE on every object in a single Active Directory domain, across all naming contexts, for least-privilege analysis.

**Consumer:** This document is consumed by Claude Code as the implementation specification. House style (`foreach`, `.Where({})`, typed collections, `CmdletBinding`, structured JSONL logging, no `Set-StrictMode`, no `ForEach-Object`/`Where-Object`) is mandatory throughout.

---

## 1. Locked-in Scope

| Decision | Value |
|---|---|
| Domain scope | Single domain (parameterized; default = current) |
| Naming contexts | All: Domain NC, Configuration NC, Schema NC, all DNS application partitions |
| SD scope | DACL + Owner (SACL and Group excluded) — Owner is captured and surfaced as a synthetic ACE row in detail CSV |
| SD control flags | Captured: `SE_DACL_PROTECTED` surfaced as `IsDaclProtected` column |
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
- SD's Group identifier (rarely meaningful in modern AD)
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
                                     # [ValidateRange(1, 32)] — values >16 typically waste effort (LDAP becomes the bottleneck)
    -PageSize             <int>      # Default: 1000 (LDAP page size)
                                     # [ValidateRange(100, 1000)] — server-side cap is 1000 in AD
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
- `New-ADExtendedRightsMap` — returns `[Dictionary[guid,PSObject]]` keyed by `rightsGuid`. Source: `CN=Extended-Rights,CN=Configuration,...`. Covers all `controlAccessRight` objects: extended rights, validated writes, AND property sets — distinguish by `validAccesses` (`0x100` = extended right, `0x08` = validated write, `0x30` = property set). Each value carries `DisplayName`, `AppliesTo` (schema GUIDs), `ValidAccesses` (mask), `RightKind` (`'ExtendedRight'`/`'ValidatedWrite'`/`'PropertySet'`).
- `New-ADSchemaGuidMap` — returns `[Dictionary[guid,PSObject]]` keyed by `schemaIDGUID`. Source: Schema NC. Each value carries `LdapDisplayName`, `ObjectCategory` (attributeSchema vs classSchema). Used to resolve **single attributes** (`ReadProperty`/`WriteProperty` ACEs targeting one attribute) and **object classes** (`CreateChild`/`DeleteChild`/`InheritedObjectType`). Property sets are **not** in this map — they're in ExtendedRightsMap.
- `New-PropertySetMembersMap` — returns `[Dictionary[guid,List[string]]]` keyed by property-set `rightsGuid`, value is the list of `lDAPDisplayName`s of member attributes. Source: Schema NC `attributeSchema` objects whose `attributeSecurityGUID` attribute is non-null — that GUID matches the property set's `rightsGuid` (an extended-right GUID, NOT a schema GUID). Reverse-indexed during construction.
- `New-WellKnownSidMap` — static `[Dictionary[string,string]]` of well-known SIDs not resolvable via `NTAccount.Translate()` reliably (S-1-5-32-* etc. usually work, but pre-populate edge cases like `S-1-3-0`/Creator Owner, `S-1-5-10`/Self, `S-1-5-9`/Enterprise DCs). See §10 for the full no-expand SID list this map must cover.

### Phase 2 — Enumeration
- `Get-ADObjectAclBatch` — paged LDAP search via `System.DirectoryServices.Protocols.LdapConnection` + `SearchRequest` + `PageResultRequestControl` + `SecurityDescriptorFlagControl(OWNER | DACL)`. Yields batches of `[List[PSObject]]` (DN, `structuralObjectClass` (with `objectClass` last-value as fallback), ObjectGUID, raw `nTSecurityDescriptor` byte[]). Implements early exit on empty result set.
  - **LDAP connection auth:** `LdapConnection.AuthType = AuthType.Negotiate` (Kerberos with NTLM fallback). Use `LdapDirectoryIdentifier` with `connectionless: $false` and `fullyQualifiedDnsHostName: $true`. LDAPS (port 636) and Basic auth are not supported in v1.
  - **Why both OWNER and DACL flags:** Owner is part of the SD and required for least-privilege analysis (the owner has implicit `READ_CONTROL`/`WRITE_DAC` regardless of DACL). Including OWNER in `SecurityDescriptorFlagControl` adds zero LDAP roundtrips — same paged search.
  - **Why S.DS.Protocols, not the AD module:** AD module's `Get-ACL` per object = 30k LDAP roundtrips. Paged S.DS.P with `SecurityDescriptorFlagControl` retrieves SD inline with the search and is 1–2 orders of magnitude faster. Memory stays bounded via paging.

### Phase 3 — ACE Parsing (runs inside runspace pool)
- `ConvertFrom-NtSecurityDescriptor` — accepts raw `byte[]`, returns a record carrying `Owner` (`SecurityIdentifier`), `Dacl` (`ActiveDirectorySecurity`), and `IsDaclProtected` (`bool`, from `ActiveDirectorySecurity.AreAccessRulesProtected` which surfaces the `SE_DACL_PROTECTED` control bit). Built via `new-object [ActiveDirectorySecurity]` + `SetSecurityDescriptorBinaryForm`. DACL + Owner.
- `Add-OwnerAce` — emits a synthetic ACE record from the parsed Owner SID: `AceType = 'Synthetic.Owner'`, `RightsDecoded = 'OwnerImplicit'`, `AccessMask = (ReadControl | WriteDacl | WriteOwner)`, `IsInherited = $false`, `IsDaclProtected = <inherited from object>`, `TrusteeSid = $owner.Value`. One synthetic row per object regardless of DACL contents.
- `ConvertFrom-AdAce` — accepts a single `ActiveDirectoryAccessRule` plus the parent object's `IsDaclProtected` flag, returns a flat `PSObject` with: `ObjectDN`, `ObjectClass`, `ObjectGUID`, `TrusteeSid`, `AccessMask`, `AccessControlType` (Allow/Deny), `AceType` (e.g., `AccessAllowedObject`), `RightsDecoded` (e.g., `GenericAll, ReadProperty, WriteProperty`), `ObjectTypeGuid`, `ObjectTypeName` (decoded via maps), `ObjectTypeKind` (Property/PropertySet/ExtendedRight/ClassChild/All/Unresolved), `InheritedObjectTypeGuid`, `InheritedObjectTypeName`, `InheritanceFlags`, `IsInherited`, `IsDaclProtected`, `AceIndex` (0-based ordinal within the source DACL), `AceFlagsRaw`.
- `Invoke-AceParsingWorkUnit` — runspace work-unit body. Accepts a batch + the GUID maps (`ExtendedRightsMap`, `SchemaGuidMap`, `PropertySetMembersMap`, passed by reference into the runspace). For each object: parse SD → emit synthetic Owner ACE → enumerate DACL ACEs → emit one record each. Returns `[List[PSObject]]` of ACE records.

### Phase 4 — Trustee Resolution
- `Resolve-TrusteeSid` — accepts SID string. Resolution order:
  1. Cache lookup
  2. `[SecurityIdentifier]::new($sid).Translate([NTAccount])`
  3. Well-known SID map
  4. ForeignSecurityPrincipals container (`CN=ForeignSecurityPrincipals,<domainNC>`)
  5. Mark as `Orphaned`
- Returns `PSObject`: `Sid`, `Name` (DOMAIN\sam or fallback), `PrincipalType` (User/Group/Computer/ManagedServiceAccount/GroupManagedServiceAccount/ForeignSecurityPrincipal/WellKnown/Orphaned/Unknown), `DistinguishedName` (when resolvable in-domain). `ManagedServiceAccount` corresponds to `objectClass=msDS-ManagedServiceAccount` (legacy sMSA); `GroupManagedServiceAccount` corresponds to `objectClass=msDS-GroupManagedServiceAccount` (current gMSA).
- `Expand-GroupTransitive` — for trustees of type Group, returns `[List[PSObject]]` of effective member principals. Use `LDAP_MATCHING_RULE_IN_CHAIN` (OID `1.2.840.113556.1.4.1941`) on `memberOf` for performance: one query per group resolves the entire transitive closure. Cache group → expanded-member-set keyed by group SID. Detect and break circular cases (the matching rule handles cycles, but cap recursion as a safety net).
- `Get-DistinctTrusteeSet` — single pass over the ACE record list to dedupe SIDs before resolving. 30k × 30 ACEs avg = ~900k ACE rows but typically <5k distinct trustees.

### Phase 5 — Inheritance Source
- `Resolve-InheritanceSource` — for each ACE where `IsInherited = $true`:
  1. If the ACE's parent object has `IsDaclProtected = $true`, log `BatchError` and mark `InheritanceSourceNote = 'InconsistentProtectedDacl'` (an inherited ACE on a protected DACL is internally inconsistent).
  2. Otherwise walk parent chain of `ObjectDN` upward.
  3. At each ancestor, direct-lookup the composite-key `$AceIndex` (see §9) by `(parent DN, TrusteeSid, AccessMask, ObjectTypeGuid)`; for each candidate verify `InheritanceFlagsPropagateTo` to the descendant.
  4. The first match walking up is by definition the **nearest** matching ancestor — record as `InheritanceSourceDN`. If none found (rare; possible with default schema ACEs that originate at the domain root or have no explicit form), record `InheritanceSourceDN = $null` and `InheritanceSourceNote = 'SchemaDefaultOrUnresolved'`.
- Index construction: build a `[Dictionary[ValueTuple[string,string,uint32,guid], List[PSObject]]]` over **explicit** ACEs only, keyed by `(ObjectDN, TrusteeSid, AccessMask, ObjectTypeGuid)`. See §9 for the algorithm. Direct lookup at each ancestor → O(n × depth); old DN-only key was O(n × depth × candidates_per_dn).

### Phase 6 — Output
- `Write-DetailCsv` — opens `StreamWriter`, writes header, streams rows. One row per `(ACE × effective trustee)`. Schema in §11.
- `Write-PivotCsv` — aggregates the in-memory ACE+trustee join. One row per effective trustee. Schema in §11.

### Cross-cutting
- `Write-LogEvent` — JSONL. Fields: `timestamp` (ISO-8601 UTC), `level`, `phase`, `event`, `message`, `data` (object). Used for milestones and errors only — no per-object spam. Emit phase-start / phase-end with counts. (Named `Write-LogEvent` — not `Write-Log` — because `Log` is not an approved PowerShell verb; PSScriptAnalyzer rule `PSUseApprovedVerbs` enforces this.)
- `New-RunspacePool` — wraps `[runspacefactory]::CreateRunspacePool`. `InitialSessionState` carries the GUID maps (`ExtendedRightsMap`, `SchemaGuidMap`, `PropertySetMembersMap`) and the well-known SID map preloaded so each runspace doesn't rebuild them.
- `Invoke-RunspacePoolWork` — generic dispatcher: accepts pool + work-unit scriptblock + collection of input batches; returns aggregated results. Uses `BeginInvoke`/`EndInvoke`. Captures per-batch failures into a separate error list (does not throw — log and continue per house style).

---

## 6. Data Structures

| Structure | Type | Purpose |
|---|---|---|
| `$NamingContexts` | `List[PSObject]` | NC list from Phase 1 |
| `$ExtendedRightsMap` | `Dictionary[guid,PSObject]` | rightsGuid → name (extended rights, validated writes, property sets) |
| `$SchemaGuidMap` | `Dictionary[guid,PSObject]` | schemaIDGUID → name (single attributes, object classes) |
| `$PropertySetMembersMap` | `Dictionary[guid,List[string]]` | property-set rightsGuid → member attribute names |
| `$WellKnownSidMap` | `Dictionary[string,string]` | SID → friendly name |
| `$AceRecords` | `List[PSObject]` | All parsed ACEs (Phase 3 output) |
| `$AceIndex` | `Dictionary[ValueTuple[string,string,uint32,guid], List[PSObject]]` | Inheritance composite-key index — see §9 |
| `$TrusteeCache` | `Dictionary[string,PSObject]` | SID → resolved principal |
| `$GroupExpansionCache` | `Dictionary[string,List[PSObject]]` | Group SID → transitive members |
| `$PivotStats` | `Dictionary[string,PSObject]` | Effective-trustee SID → running aggregates (built during streaming detail write — see §12) |
| `$ErrorBag` | `List[PSObject]` | Captured errors |

Memory note: 900k ACE rows × ~400 bytes ≈ ~360 MB pre-expansion. Acceptable on an admin workstation. **Detail rows are NOT materialised in memory** — Phase 6 streams `(ACE × effective trustee)` rows directly to the detail CSV `StreamWriter` while updating `$PivotStats` aggregates incrementally (see §12). Worst-case 5M expanded rows would be ~2 GB if held; streaming caps peak memory at the aggregate state size (~5k trustees × few KB ≈ ~5 MB). After detail CSV is written, the script writes pivot from `$PivotStats` and clears all caches via `Remove-Variable`.

---

## 7. ACE Decoding Rules

For each `ActiveDirectoryAccessRule`:

**RightsDecoded** — bitwise decompose `ActiveDirectoryRights`:
- Generic: `GenericAll`, `GenericRead`, `GenericWrite`, `GenericExecute`
- Standard: `Delete`, `ReadControl`, `WriteDacl`, `WriteOwner`, `Synchronize`, `AccessSystemSecurity`
- Object-specific: `CreateChild`, `DeleteChild`, `ListChildren`, `Self`, `ReadProperty`, `WriteProperty`, `DeleteTree`, `ListObject`, `ExtendedRight`
- Emit comma-delimited string of present flags.

**ObjectType GUID interpretation** — depends on `AceType` and `RightsDecoded`:

| Right | ObjectType GUID means | Resolution order |
|---|---|---|
| `ExtendedRight` | Extended right or validated write | ExtendedRightsMap (`validAccesses=0x100` or `0x08`) |
| `ReadProperty` / `WriteProperty` | Property set OR single attribute | 1. ExtendedRightsMap with `validAccesses=0x30` → property set (also list members from `PropertySetMembersMap`); 2. SchemaGuidMap → single attribute; 3. else → unresolved |
| `CreateChild` / `DeleteChild` | Child object class | SchemaGuidMap (filtered to `classSchema`) |
| `Self` | Validated write | ExtendedRightsMap (`validAccesses=0x08`) |
| (none / zero GUID) | Applies to all properties / all child types | — |

**InheritedObjectType GUID** — only meaningful for ACEs that propagate; identifies the child class the ACE applies to when inherited (e.g., "applies to descendant `user` objects only"). Resolve via SchemaGuidMap (`classSchema` filter).

`ObjectTypeKind` field disambiguates which lookup produced the name. Values: `Property` (single attribute), `PropertySet`, `ExtendedRight`, `ValidatedWrite`, `ClassChild`, `All` (zero GUID), `Unresolved` (no map hit — record raw GUID for forensics).

**`IsDaclProtected` propagation** — every ACE record carries the parent object's `IsDaclProtected` flag (extracted in Phase 3 from `ActiveDirectorySecurity.AreAccessRulesProtected`). When `true`, the object's DACL is shielded from inheritance (`SE_DACL_PROTECTED` / "Disable inheritance" in the GUI), and no inherited ACEs should appear on it. The Phase 5 inheritance-source resolver uses this as an internal-consistency check (see §9).

---

## 8. GUID Map Construction Details

**ExtendedRightsMap source:**
- LDAP search: `CN=Extended-Rights,CN=Configuration,<forestDN>`
- Filter: `(objectClass=controlAccessRight)`
- Attributes: `cn`, `displayName`, `rightsGuid`, `appliesTo`, `validAccesses`
- Key: `[guid]$rightsGuid`
- Covers all three kinds of `controlAccessRight`:
  - **Extended rights** — `validAccesses = 0x100` (`ADS_RIGHT_DS_CONTROL_ACCESS`). Examples: `User-Force-Change-Password`, `DS-Replication-Get-Changes-All` (DCSync).
  - **Validated writes** — `validAccesses = 0x08` (`ADS_RIGHT_DS_SELF`). Examples: `Validated-DNS-Host-Name`, `Self-Membership`.
  - **Property sets** — `validAccesses = 0x30` (`ADS_RIGHT_DS_READ_PROP | ADS_RIGHT_DS_WRITE_PROP`). Examples: `Personal-Information`, `Phone-and-Mail-Options`.
- Each value carries `RightKind` field (`'ExtendedRight'`/`'ValidatedWrite'`/`'PropertySet'`) derived from `validAccesses` to simplify §7 lookup logic.

**SchemaGuidMap source:**
- LDAP search: `<schemaNC>`
- Filter: `(|(objectClass=attributeSchema)(objectClass=classSchema))`
- Attributes: `lDAPDisplayName`, `schemaIDGUID`, `objectClass`
- Key: `[guid][byte[]]$schemaIDGUID`
- Each value carries `LdapDisplayName` and `ObjectCategory` (`'attributeSchema'` or `'classSchema'`).
- **Does NOT contain property sets.** Property sets are `controlAccessRight` objects in the Configuration NC (Extended-Rights container), not schema objects. They live in ExtendedRightsMap. The link from a member attribute to its property set is via the property set's `rightsGuid` (an extended-right GUID), not its `schemaIDGUID`.

**PropertySetMembersMap source:**
- LDAP search: `<schemaNC>`
- Filter: `(&(objectClass=attributeSchema)(attributeSecurityGUID=*))` — only attributes that are members of a property set
- Attributes: `lDAPDisplayName`, `attributeSecurityGUID`
- Key: `[guid][byte[]]$attributeSecurityGUID` (= the property set's `rightsGuid`)
- Value: `List[string]` of `lDAPDisplayName`s of attributes belonging to that property set.
- Built as a reverse index: each row contributes one entry to the list under its property set's key.

**Page size:** 1000 for all three. Maps are bounded: ~hundreds for extended rights, ~3000 for schema, ~hundreds of distinct property sets each with a few to dozens of member attributes.

---

## 9. Inheritance Source Resolution — Algorithm

**Index construction (before the resolution loop):**

Build a composite-key index over **explicit** ACEs only:

```
$AceIndex = Dictionary[ValueTuple[string, string, uint32, guid], List[PSObject]]()

foreach ($ace in $AceRecords) {
    if ($ace.IsInherited) { continue }
    $key = [ValueTuple[string, string, uint32, guid]]::new(
        $ace.ObjectDN,        # parent DN we'll lookup
        $ace.TrusteeSid,
        $ace.AccessMask,
        $ace.ObjectTypeGuid ?? [guid]::Empty
    )
    if (-not $AceIndex.ContainsKey($key)) {
        $AceIndex[$key] = [List[PSObject]]::new()
    }
    $AceIndex[$key].Add($ace)
}
```

This trades a small amount of memory for direct-lookup match (no `.Where()` scan per ancestor). Worst-case complexity drops from O(n × depth × candidates_per_dn) ≈ ~90M ops at the design ceiling to O(n × depth) ≈ ~9M ops.

**Resolution loop:**

```
For each ACE where IsInherited = true:
    if ACE.IsDaclProtected:
        # Internal-consistency check: a DACL_PROTECTED object should have
        # NO inherited ACEs. If we see one, log a BatchError — likely a
        # malformed SD or a parser bug.
        Log-BatchError 'InheritedAceOnProtectedDacl' $ACE
        ACE.InheritanceSourceDN = null
        ACE.InheritanceSourceNote = 'InconsistentProtectedDacl'
        continue

    parent = Parent(ACE.ObjectDN)
    while parent is not null and parent is within any enumerated NC:
        key = (parent, ACE.TrusteeSid, ACE.AccessMask, ACE.ObjectTypeGuid ?? Empty)
        candidates = $AceIndex[key]  # may be empty
        match = candidates.Where({
            InheritanceFlagsPropagateTo(parent, ACE.ObjectDN, ACE.ObjectClass, $_.InheritanceFlags, $_.InheritedObjectTypeGuid)
        })
        if match.Count -gt 0:
            ACE.InheritanceSourceDN = parent
            break    # first match walking up is by definition the nearest ancestor
        parent = Parent(parent)
    if not found:
        ACE.InheritanceSourceDN = null
        ACE.InheritanceSourceNote = 'SchemaDefaultOrUnresolved'
```

`InheritanceFlagsPropagateTo` is a helper that checks `ContainerInherit` / `ObjectInherit` / `InheritOnly` / `NoPropagateInherit` flags and the `InheritedObjectType` class filter against the descendant's class.

**Edge cases to handle:**
- ACEs originating from `defaultSecurityDescriptor` of the schema class (no explicit parent ACE exists for these — they're materialized at object creation). Mark `SchemaDefaultOrUnresolved`.
- Multiple matching ancestors (e.g., same ACE explicitly placed at two levels): record the **nearest matching ancestor** — the one closest to the descendant by parent-chain distance. The walk-up algorithm finds it first by construction.
- Inherited ACE seen on a `DACL_PROTECTED` object: log `BatchError` and mark `InheritanceSourceNote = 'InconsistentProtectedDacl'`. Should not occur for a well-formed SD.
- ACEs on cross-NC objects (rare): stay within the originating NC.

---

## 10. Orphaned/Unresolvable SID Handling — Recommendation

Categorize every trustee into exactly one `PrincipalType`:

| Category | Detection |
|---|---|
| `User` / `Group` / `Computer` | Resolved via in-domain LDAP lookup; `objectClass` determines type |
| `ManagedServiceAccount` | `objectClass = msDS-ManagedServiceAccount` (legacy sMSA) |
| `GroupManagedServiceAccount` | `objectClass = msDS-GroupManagedServiceAccount` (current gMSA) |
| `WellKnown` | Resolved via `NTAccount.Translate()` to `BUILTIN\*` or `NT AUTHORITY\*`, or matched in WellKnownSidMap |
| `ForeignSecurityPrincipal` | Found as object under `CN=ForeignSecurityPrincipals,<domainNC>` |
| `Orphaned` | All resolution paths failed; SID format valid; likely deleted account |
| `Unknown` | All resolution failed and SID itself is malformed (should never happen but handle defensively) |

Output row always contains the raw SID string regardless of category. Orphaned trustees still get a row in the detail CSV — they are exactly the kind of finding least-privilege reviews want to surface. Pivot CSV groups orphans together for visibility.

Do not throw on unresolvable SIDs. Log one structured event per distinct orphan SID at INFO level (`event: "OrphanSid"`).

### Well-known SIDs that MUST NOT be transitively expanded

Treat the following as terminal trustees in detail/pivot CSVs (no group-membership expansion). These either have implicit/runtime-computed memberships not retrievable via `LDAP_MATCHING_RULE_IN_CHAIN`, or have memberships so large that expansion produces a meaningless explosion of rows.

```
Cross-domain / well-known (full SIDs):
  S-1-1-0   Everyone
  S-1-5-7   Anonymous Logon
  S-1-5-11  Authenticated Users
  S-1-5-2   Network
  S-1-5-4   Interactive
  S-1-5-9   Enterprise Domain Controllers
  S-1-5-10  Self / Principal Self
  S-1-3-0   Creator Owner
  S-1-3-1   Creator Group

Domain-relative (RID; prefix with current domain SID at runtime):
  -498  Enterprise Read-only Domain Controllers
  -513  Domain Users
  -514  Domain Guests
  -515  Domain Computers
  -516  Domain Controllers
  -521  Read-only Domain Controllers

BUILTIN aliases (S-1-5-32-*): treat as terminal — they resolve via NTAccount.Translate()
to local-machine groups and have no AD-wide membership semantics relevant to AD ACL analysis.
```

Implementation: a single `[HashSet[string]]` of full SIDs (well-known) plus a list of RIDs to combine with the runtime-discovered domain SID. `Resolve-TrusteeSid` checks this set before invoking `Expand-GroupTransitive`; matched trustees are returned with `EffectiveTrusteeSid = AceTrusteeSid` (themselves) and `IsThroughGroup = $false`.

---

## 11. Output Schema

### Detail CSV — `ADPermissions_Detail_<timestamp>.csv`

One row per `(target object × ACE × effective trustee)` after group expansion.

| Column | Type | Notes |
|---|---|---|
| `ObjectDN` | string | Target object DN |
| `ObjectClass` | string | `structuralObjectClass` if present; else last value of `objectClass` |
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
| `AceType` | string | E.g., `AccessAllowedObject`, `AccessDeniedObject`, or `Synthetic.Owner` |
| `AceIndex` | int | 0-based ordinal of the ACE within the source DACL (before group expansion). For `Synthetic.Owner` rows: `-1`. |
| `AccessControlType` | string | Allow / Deny |
| `RightsDecoded` | string | Comma-delimited rights. For `Synthetic.Owner`: `'OwnerImplicit'` |
| `AccessMask` | uint32 | Raw mask for diffing. For `Synthetic.Owner`: `(ReadControl \| WriteDacl \| WriteOwner)` |
| `ObjectTypeGuid` | guid? | |
| `ObjectTypeName` | string | Decoded |
| `ObjectTypeKind` | string | Property / PropertySet / ExtendedRight / ValidatedWrite / ClassChild / All / Unresolved |
| `InheritedObjectTypeGuid` | guid? | |
| `InheritedObjectTypeName` | string | |
| `IsInherited` | bool | |
| `IsDaclProtected` | bool | True if the parent object's DACL has `SE_DACL_PROTECTED` set (inheritance disabled). All ACEs on a protected object share the same value. |
| `InheritanceSourceDN` | string | Empty for explicit; populated for inherited |
| `InheritanceSourceNote` | string | E.g., `SchemaDefaultOrUnresolved`, `InconsistentProtectedDacl` |
| `InheritanceFlags` | string | ContainerInherit / ObjectInherit / etc. |
| `AceFlagsRaw` | byte | Raw byte for forensics |
| `CollectedAt` | datetime | UTC ISO-8601 |

**Synthetic Owner row:** every object emits exactly one row with `AceType = 'Synthetic.Owner'` capturing the SD's owner. The owner has implicit `READ_CONTROL`/`WRITE_DAC`/`WRITE_OWNER` regardless of DACL, so this row makes that access path visible in least-privilege analysis. `AceIndex = -1` distinguishes it from real DACL ACEs (which start at 0).

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
- **Stream-and-write per ACE** (Phase 6): expand-and-write per ACE rather than building the full expanded list in memory. Pivot accumulates aggregates as detail rows are emitted, avoiding a second pass and keeping peak memory bounded at the aggregate state size (~5k trustees × few KB ≈ ~5 MB).

**Phase 6 streaming pattern:**
```
$detailWriter = [StreamWriter]::new($detailPath, $false, [Text.Encoding]::UTF8)
$detailWriter.WriteLine($DETAIL_HEADER)
$pivotStats = [Dictionary[string, PSObject]]::new()

foreach ($ace in $AceRecords) {
    $effective = Resolve-EffectiveTrustees $ace      # expand groups (Phase 4 cache)
    foreach ($et in $effective) {
        Write-DetailRow -Writer $detailWriter -Ace $ace -EffectiveTrustee $et
        Update-PivotAggregate -Stats $pivotStats -EffectiveTrustee $et -Ace $ace
    }
}
$detailWriter.Flush(); $detailWriter.Dispose()

# Pivot is now ready in $pivotStats — no second pass over $AceRecords needed
Write-PivotCsv -Path $pivotPath -Stats $pivotStats
```

This caps detail-side peak memory at the size of `$AceRecords` (pre-expansion ~360 MB) rather than 5M expanded rows × ~400 bytes ≈ ~2 GB.

**Early exits:** If any NC returns zero objects, log and skip. If the GUID maps are empty (corrupt schema or insufficient rights), throw — this is unrecoverable per house style.

---

## 13. Logging (JSONL)

Implemented by `Write-LogEvent` (named to satisfy `PSUseApprovedVerbs` — `Log` is not an approved PowerShell verb). One event per line. Required fields: `timestamp` (ISO-8601 UTC), `level`, `phase`, `event`, `message`. Optional: `data` (nested object), `correlationId`.

**Events to emit (and only these — no per-object logging):**
- `ScriptStart` (params summary)
- `PhaseStart` / `PhaseEnd` for each of the 6 phases (with counts and elapsed ms in `data`)
- `NamingContextDiscovered` (one per NC)
- `MapBuilt` (extended rights count, schema GUID count, property-set count)
- `EnumerationProgress` (every N batches, e.g., every 5000 objects)
- `OrphanSid` (one per distinct orphan)
- `BatchError` (per-batch parse failures from runspaces; also `InheritedAceOnProtectedDacl` per §9 inconsistency check)
- `ScriptEnd` (totals, elapsed, output paths)

Levels: `INFO`, `WARN`, `ERROR`. No `DEBUG` chatter at default verbosity.

**Console progress:** for the enumeration phase (potentially minutes-long on a 30k-object domain), emit `Write-Progress` ticks at the same cadence as `EnumerationProgress` JSONL events: per-NC percentage complete, current batch index, elapsed time. Do NOT use `Write-Host` (PSScriptAnalyzer rule `PSAvoidUsingWriteHost`). `Write-Progress` is the correct stream for interactive progress and is suppressed cleanly in non-interactive runs.

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

**Exit codes (for CLI / CI consumers):**

| Code | Meaning |
|---|---|
| 0 | Success — `errorCount = 0` |
| 1 | Unrecoverable error — LDAP bind, RootDSE read, schema/extended-rights query empty, CSV write failure |
| 2 | Success-with-warnings — `errorCount > 0` (partial inventory written; check log to see which objects failed) |

Implemented via `try`/`catch` at top level: re-throw unrecoverable errors (PowerShell surfaces these as exit 1 by default, but explicit `exit 1` in the top-level catch makes it deterministic). At end of script: `if ($ErrorBag.Count -gt 0) { exit 2 } else { exit 0 }`.

---

## 15. Dependencies

**Required:**
- **Operating system: Windows.** PowerShell 7+ on Windows. Required for `System.DirectoryServices.ActiveDirectorySecurity` parsing and `NTAccount.Translate()` SID resolution. Linux/macOS PowerShell 7 will load the type but fail at the parsing step — the script is Windows-only. (Verified empirically via CI: Ubuntu test job failed; switched to `windows-latest`.) Add to script header: `# Windows-only — uses System.DirectoryServices types not available on .NET on Linux/macOS.`
- PowerShell 7+
- .NET assemblies (built-in): `System.DirectoryServices`, `System.DirectoryServices.Protocols`, `System.Security.Principal`
- Network reachability to a writable DC for the target domain on **port 389** (LDAP). Port 9389 (ADWS) is NOT used.

**Authentication:** Kerberos (Negotiate) only — `LdapConnection.AuthType = AuthType.Negotiate`. NTLM fallback within Negotiate is acceptable. LDAPS (port 636) and Basic auth are not supported in v1.

**Optional / not used:**
- `ActiveDirectory` PowerShell module — **not required**. The script uses S.DS.P directly for performance and to avoid the module's per-call overhead. If a function genuinely benefits from it (e.g., a fallback `Get-ADObject` for niche resolution), gate behind a capability check — do not hard-require.

**Permissions needed by the executing principal:**
- Read access to all enumerated NCs (Domain, Configuration, Schema, DNS partitions)
- Read access to `nTSecurityDescriptor` attribute on all objects (this is the non-trivial requirement — typically requires Domain Admins or an explicitly delegated principal). Document this prominently in script help.

---

## 16. Open Questions / Decisions Deferred

These were not raised during planning. Implementation may proceed with the noted defaults, but flag them at the top of the script header so future maintainers see them.

1. **ACE deduplication for identical inherited ACEs from the same source** — when two parent containers contribute the same logical ACE to a descendant (rare but possible with explicit ACE replication), do we emit two rows or one with merged source DNs? **Default:** emit one row per logical ACE, with `InheritanceSourceDN` set to the nearest match (per §9 algorithm).
2. **Deny ACE precedence** — the report includes both Allow and Deny ACEs but does not compute *effective* access (which would require resolving Allow/Deny conflicts per Windows access-check semantics). Inventory only.
3. **Well-known trustee expansion** — well-known SIDs (Domain Users, Authenticated Users, Everyone, etc.) and BUILTIN aliases are treated as terminal trustees and not transitively expanded. The full skip list is enumerated in §10. Configurable via a future flag if needed.
4. **Tombstoned object handling** — deleted-objects container is *not* enumerated by default. Confirm this is desired.

---

## 17. Validation

No live-LDAP smoke run is in scope: there is no lab DC available to this project. End-to-end validation against a real directory and the 30k-object performance pass are removed deliverables, not deferred ones. If a lab DC becomes available later, validation can be re-added as a new section and as additional steps in §18 — but until then, the implementation's correctness rests entirely on the Pester unit suites attached to each phase.

The unit suites that ship with the implementation cover, at the helper-function level:

- Phase 1: GUID-map builders (Extended-Rights, Schema, PropertySet members) and well-known SID map.
- Phase 2: paged-search shape, batch boundaries, raw-byte SD passthrough, GUID conversion, `structuralObjectClass` fallback.
- Phase 3: SD parsing, synthetic Owner row shape, RightsDecoded composition, all five `ObjectTypeKind` classifications, `AceFlagsRaw` composition, PARSE_ERROR isolation, runspace-pool aggregation, BatchError capture.
- Phase 4: trustee resolution cascade (cache → Translate → WellKnownSid → FSP → Orphan), well-known SID skip-set, in-chain group expansion with cycle/cap behaviour.
- Phase 5: composite-key index over explicit rows only, escape-aware `Get-ParentDistinguishedName`, `Test-InheritanceFlagsPropagateTo` flag-bit + class-filter rule, `Resolve-InheritanceSource` direct-parent / level-2 walk / DACL_PROTECTED short-circuit / `SchemaDefaultOrUnresolved` fallback.
- Phase 6: RFC-4180 escape, Detail-CSV column shape, Synthetic.Owner / PARSE_ERROR / inherited row passthrough, group fan-out, NC-label longest-suffix match, pivot accumulator counters, pivot summary formatters with sort tiebreaks, full pivot/detail reconciliation on a fixture (`sum(stats[*].TotalAceCount) == row count`).

Anything that depends on real-directory state — schema-default ACE handling on a fresh user, DACL_PROTECTED + Convert anomaly behaviour, transitive expansion correctness on real nested groups, property-set name resolution for a real PropertySetMembersMap, throughput on a 30k-object domain — is **uncovered** by this plan. The script's behaviour on those cases is asserted by the unit suites against fabricated SDs; behaviour on real SDs is unverified. Operators running this against a production directory should treat the first run as exploratory and review the JSONL log for `BatchError` / `PARSE_ERROR` / `OrphanSid` / `InheritedAceOnProtectedDacl` events before acting on the CSV output.

---

## 18. Implementation Order for Claude Code

Build in this sequence so each phase is independently testable:

1. Parameters + script skeleton + `Write-LogEvent`
2. Phase 1: NC discovery + GUID maps — `ExtendedRightsMap`, `SchemaGuidMap`, `PropertySetMembersMap` (testable standalone)
3. Phase 2: Enumeration with `SecurityDescriptorFlagControl(OWNER | DACL)` (testable: count objects per NC)
4. Phase 3: SD parsing (`ConvertFrom-NtSecurityDescriptor` returns Owner + DACL + IsDaclProtected) and ACE parsing including synthetic `Add-OwnerAce` — first single-threaded, then wrap in runspace pool
5. Phase 4: Trustee resolution + group expansion + well-known SID skip list (testable: known group SID → expected member list; well-known group → terminal)
6. Phase 5: Inheritance source resolution with composite-key index + DACL_PROTECTED short-circuit
7. Phase 6: Detail CSV writer (streaming, with `AceIndex` and `IsDaclProtected` columns and `Synthetic.Owner` rows)
8. Phase 6: Pivot CSV writer (built incrementally during detail streaming via `$PivotStats`)

Do not skip ahead. Each phase commits independently.

Step 8 is the final implementation step. There is no end-to-end smoke run and no 30k-object performance pass — both required a lab DC that is not available to this project (see §17). If lab access becomes available later, those validations would be additive new steps; they are not preconditions for considering the implementation complete.
