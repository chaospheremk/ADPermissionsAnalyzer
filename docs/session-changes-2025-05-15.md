# Session Changes — 2025-05-15

All changes made during the debugging and memory-hygiene session.
Target runtime: PowerShell 7.5.4 / .NET 9 on Windows Server.

---

## Category 1: PS 7.5.4 Fully-Qualified Type Names

**Problem:** PS 7.5.4 uses lazy compilation for dot-sourced files — function
bodies aren't compiled until first invocation. By that point the
`using namespace System.DirectoryServices.Protocols` directive's scope has
been lost, causing `TypeNotFound` errors for short type names like
`[SearchRequest]`, `[SearchScope]`, etc.

**Fix:** Replaced every short SDP type name with its fully-qualified form
and removed the now-unnecessary `using namespace` directives.

### scripts/lib/Phase1-DiscoveryAndMaps.ps1

| # | Short Name | Fully-Qualified Name |
|---|-----------|----------------------|
| 1 | `[LdapDirectoryIdentifier]` | `[System.DirectoryServices.Protocols.LdapDirectoryIdentifier]` |
| 2 | `[LdapConnection]` | `[System.DirectoryServices.Protocols.LdapConnection]` |
| 3 | `[AuthType]::Negotiate` | `[System.DirectoryServices.Protocols.AuthType]::Negotiate` |
| 4 | `[SearchRequest]` (in Read-LdapEntry) | `[System.DirectoryServices.Protocols.SearchRequest]` |
| 5 | `[SearchScope]::Subtree` (in Read-LdapEntry) | `[System.DirectoryServices.Protocols.SearchScope]::Subtree` |
| 6 | `[PageResultRequestControl]` | `[System.DirectoryServices.Protocols.PageResultRequestControl]` |
| 7 | `[SearchResponse]` | `[System.DirectoryServices.Protocols.SearchResponse]` |
| 8 | `[PageResultResponseControl]` | `[System.DirectoryServices.Protocols.PageResultResponseControl]` |
| 9 | `[SearchRequest]` (in Get-ADNamingContext) | `[System.DirectoryServices.Protocols.SearchRequest]` |
| 10 | `[SearchScope]::Base` (in Get-ADNamingContext) | `[System.DirectoryServices.Protocols.SearchScope]::Base` |
| 11 | `[SearchResponse]` (in Get-ADNamingContext) | `[System.DirectoryServices.Protocols.SearchResponse]` |
| 12 | `[SearchRequest]` (in New-ADExtendedRightsMap) | `[System.DirectoryServices.Protocols.SearchRequest]` |
| 13 | `[SearchScope]` (in New-ADSchemaGuidMap) | `[System.DirectoryServices.Protocols.SearchScope]` |
| 14 | `[SearchRequest]` (in New-ADSchemaGuidMap) | `[System.DirectoryServices.Protocols.SearchRequest]` |

- Removed: `using namespace System.DirectoryServices.Protocols` (top of file)
- Kept: `using namespace System.Collections.Generic`

### scripts/lib/Phase2-Enumeration.ps1

| # | Short Name | Fully-Qualified Name |
|---|-----------|----------------------|
| 1 | `[SecurityDescriptorFlagControl]` | `[System.DirectoryServices.Protocols.SecurityDescriptorFlagControl]` |
| 2 | `[SecurityMasks]` | `[System.DirectoryServices.Protocols.SecurityMasks]` |
| 3 | `[DirectoryControl]` (array type) | `[System.DirectoryServices.Protocols.DirectoryControl]` |

- Removed: `using namespace System.DirectoryServices.Protocols`

### scripts/lib/Phase4-TrusteeResolution.ps1

| # | Short Name | Fully-Qualified Name |
|---|-----------|----------------------|
| 1 | `[SearchScope]::Base` | `[System.DirectoryServices.Protocols.SearchScope]::Base` |

- Removed: `using namespace System.DirectoryServices.Protocols`

---

## Category 2: LDAP Connection Fixes

All changes in `scripts/lib/Phase1-DiscoveryAndMaps.ps1`, function
`Connect-AdLdap`.

### 2a. LdapDirectoryIdentifier connectionless parameter

**Problem:** `connectionless: $true` creates a UDP-based LDAP connection.
Active Directory requires TCP for paged searches, extended controls, and
binary attribute retrieval.

**Fix:** Changed `connectionless` from `$true` to `$false` in the
`[LdapDirectoryIdentifier]::new()` call.

### 2b. Missing ProtocolVersion = 3

**Problem:** The default protocol version is 2. LDAPv3 is required for
paged result controls and security descriptor controls used by Phase 2.

**Fix:** Added `$connection.SessionOptions.ProtocolVersion = 3` after
`LdapConnection` construction.

### 2c. Referral chasing causing paging failures

**Problem:** Default referral chasing (`All`) followed subordinate referrals
to `DomainDnsZones` and `ForestDnsZones` application partitions. This
inflated page-1 results (returned 5000 entries instead of the expected
~1000) and corrupted the paging continuation cookie, causing page-2 to
fail with an `LdapException`.

**Fix:** Added
`$connection.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None`
to `Connect-AdLdap`.

---

## Category 3: SearchRequest Constructor / Attribute Fixes

All changes in `scripts/lib/Phase1-DiscoveryAndMaps.ps1`.

### 3a. SearchRequest attributes double-wrapping

**Problem:** Passing `[string[]]` directly to the `SearchRequest` constructor
caused PowerShell to wrap the array in another array (the constructor's
`params string[]` overload). This resulted in malformed attribute lists.

**Fix:** Changed to `$null` for the constructor's attributes parameter, then
used `$request.Attributes.AddRange($attrs)` to add attributes after
construction. Applied in both `Read-LdapEntry` and `Get-ADNamingContext`.

### 3b. Attribute value unwrapping in Read-LdapEntry

**Problem:** Attribute values retrieved from `SearchResultEntry.Attributes`
were not being unwrapped from their `DirectoryAttribute` containers
correctly, producing unexpected types downstream.

**Fix:** Added explicit `[string[]]` and `[object[]]` casts on direct
assignments inside the if/else branches of the attribute extraction loop
in `Read-LdapEntry`.

---

## Category 4: Runtime Assembly Loading

### scripts/Invoke-ADPermissionAnalysis-Core.ps1

**Problem:** `using assembly System.DirectoryServices.Protocols` at the top
of a script does not work reliably on PS 7.5.4 — the assembly may not be
loaded before dot-sourced lib files reference its types.

**Fix:** Added `Add-Type -AssemblyName System.DirectoryServices.Protocols`
before the dot-source block that loads Phase 1–6 lib files. This ensures
the SDP types are available at runtime when the lib functions are first
invoked.

---

## Category 5: Memory Hygiene — Mid-Enumeration Drain

**Problem:** The Phase 2→3 pipeline accumulated ALL submitted runspace work
items in `$handles` without draining any until enumeration finished. Then
`Receive-RunspaceHandle` collected ALL parsed ACE records into a single
`$aceRecords` list. For large domains this caused 8+ GB memory consumption
and process kills.

### 5a. Removed `Item` from runspace handle (Phase3-AceParsing.ps1)

**What:** Removed `Item = $Item` from the `[PSCustomObject]` returned by
`Submit-RunspaceWorkItem`.

**Why:** Every handle was pinning a reference to its input batch (250
objects with binary nTSecurityDescriptor blobs). This data was never read
after submission — `Receive-RunspaceHandle` does not access `$h.Item` —
but the reference prevented GC from collecting the batch data after the
runspace finished processing it.

Updated the function's docstring to reflect the new output shape
(`{PowerShell, Handle, Index, Metadata}` instead of
`{PowerShell, Handle, Item, Index, Metadata}`).

### 5b. Pre-initialized `$aceRecords` and tracking variables (Core.ps1)

**What:** Moved `$aceRecords = [List[PSObject]]::new()` before the
enumeration loop. Added `$totalBatches = 0` counter and
`$drainThreshold = [Math]::Max($ThreadCount * 2, 8)`.

**Why:** Allows incremental collection of parsed ACE records during
enumeration instead of a single bulk allocation after. The threshold caps
how many in-flight PowerShell pipelines exist simultaneously.

### 5c. Mid-enumeration drain loop (Core.ps1)

**What:** After each batch submit, when `$handles.Count -ge $drainThreshold`,
scans `$handles` backwards for completed handles
(`$h.Handle.IsCompleted`). For each completed handle: calls `EndInvoke`,
appends results to `$aceRecords`, logs errors to `$script:ErrorBag`,
disposes the PowerShell pipeline, and removes the handle from the list.

**Why:** Caps the number of live `[powershell]` instances to roughly
`2× ThreadCount`. Frees pipeline memory and internal buffers as runspaces
complete, rather than holding hundreds of disposed-but-referenced pipeline
objects until the end.

### 5d. Final drain replacement (Core.ps1)

**What:** Replaced the single `$aceRecords = Receive-RunspaceHandle ...`
call with a conditional block: if `$handles.Count -gt 0`, calls
`Receive-RunspaceHandle` for remaining in-flight handles and appends
results to the existing `$aceRecords` list, then clears `$handles`.

**Why:** After mid-enumeration drains, only a few handles remain in-flight.
The final drain collects these stragglers and appends to the already-
populated `$aceRecords` rather than creating a new list.

### 5e. Fixed `batchCount` in Phase 3 end log (Core.ps1)

**What:** Changed `batchCount = $handles.Count` to
`batchCount = $totalBatches` in the Phase 3 PhaseEnd log event.

**Why:** After draining, `$handles` is empty — the count would always be 0.
`$totalBatches` tracks the true number of batches submitted.

### 5f. Enriched progress logging (Core.ps1)

**What:** Added `pendingDrains = $handles.Count` and
`acesCollected = $aceRecords.Count` to the Phase 2 progress log data.
Updated the `Write-Progress` `CurrentOperation` string to include pending
handle count and ACE count.

**Why:** Provides visibility into memory pressure during long-running
enumeration passes.
