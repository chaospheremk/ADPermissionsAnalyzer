#Requires -Version 7.0
using namespace System.Collections.Generic
using namespace System.Security.Principal
using namespace System.Text

# SDP types use fully-qualified names — see Phase1-DiscoveryAndMaps.ps1 header
# and docs/session-changes-2025-05-15.md §1.

<#
.SYNOPSIS
    Phase 4 helpers for AD Permissions Analyzer: trustee SID resolution,
    transitive group expansion, and the well-known-SID skip set.

.DESCRIPTION
    Implements §5 Phase 4, §10 (orphan + skip-set rules), and the
    sMSA/gMSA classification from docs/AD-Permissions-Analyzer-Plan.md.

    IO boundaries kept narrow for testability:
      - Resolve-NTAccount wraps [SecurityIdentifier].Translate([NTAccount])
        (the local LSA hit) so unit tests can mock it without a domain.
      - All LDAP traffic goes through Invoke-PagedLdapSearch (Phase 1) so
        tests mock at that single boundary.

    Phase 4 runs single-threaded over $aceRecords and never mutates them;
    Phase 6 is the consumer that joins each ACE to its effective trustees
    while streaming the detail CSV.
#>

function Resolve-NTAccount {
    <#
    .SYNOPSIS
        Translate a SID string to a DOMAIN\sam form via the local LSA.

    .DESCRIPTION
        Thin wrapper around [SecurityIdentifier]::new($Sid).Translate([NTAccount])
        so the LSA hit is mockable in unit tests (Translate is not reliably
        exercisable offline). Throws when the SID is unmappable — callers
        catch and fall through the Resolve-TrusteeSid plan-§5 cascade.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Sid
    )

    $sidObj = [SecurityIdentifier]::new($Sid)
    $sidObj.Translate([NTAccount]).Value
}

function ConvertTo-LdapBinaryFilter {
    <#
    .SYNOPSIS
        Encode a SID string as the escaped \xx\xx... literal an LDAP filter
        expects when matching against an octet-string attribute (objectSid).

    .DESCRIPTION
        SecurityIdentifier.GetBinaryForm produces the canonical 28-byte form;
        each byte is rendered as \HH so the filter
        '(objectSid=\01\05\00\...)' matches exactly the same bytes the
        directory stores. Used by Resolve-DomainPrincipal.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Sid
    )

    $sidObj = [SecurityIdentifier]::new($Sid)
    $bytes  = [byte[]]::new($sidObj.BinaryLength)
    $sidObj.GetBinaryForm($bytes, 0)

    $sb = [StringBuilder]::new($bytes.Length * 3)
    foreach ($b in $bytes) {
        [void] $sb.AppendFormat('\{0:x2}', $b)
    }
    $sb.ToString()
}

function Get-PrincipalTypeFromObjectClass {
    <#
    .SYNOPSIS
        Classify a directory object as User / Group / Computer / sMSA / gMSA
        / Unknown from its objectClass list.

    .DESCRIPTION
        Pure function: the categorisation rule is testable without a live
        directory or any LDAP fixture. msDS-* classes are checked before
        their inherited base classes (computer / user / group) because
        msDS-GroupManagedServiceAccount inherits from computer and
        msDS-ManagedServiceAccount inherits from user — without explicit
        priority the gMSA/sMSA distinction is silently lost.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $ObjectClasses
    )

    if     ($ObjectClasses -contains 'msDS-GroupManagedServiceAccount') { 'GroupManagedServiceAccount' }
    elseif ($ObjectClasses -contains 'msDS-ManagedServiceAccount')      { 'ManagedServiceAccount' }
    elseif ($ObjectClasses -contains 'computer')                        { 'Computer' }
    elseif ($ObjectClasses -contains 'group')                           { 'Group' }
    elseif ($ObjectClasses -contains 'user')                            { 'User' }
    else                                                                { 'Unknown' }
}

function Get-DomainSid {
    <#
    .SYNOPSIS
        Read the domain SID from objectSid on the domain NC root.

    .DESCRIPTION
        The skip set in plan §10 is composed of universal SIDs plus
        domain-RID-resolved entries (-498/-513/-514/-515/-516/-521).
        Resolving the runtime domain SID via a base-scope read on the
        domain NC root is the most direct path: one entry, one byte[]
        attribute, no enumeration. Throws if the read returns nothing
        (unrecoverable per plan §14 — same class as the RootDSE failure).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Connection,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $DomainNamingContext
    )

    $searchParams = @{
        Connection       = $Connection
        SearchBase       = $DomainNamingContext
        Filter           = '(objectClass=*)'
        Attributes       = @('objectSid')
        BinaryAttributes = @('objectSid')
        Scope            = [System.DirectoryServices.Protocols.SearchScope]::Base
    }
    $entries = Invoke-PagedLdapSearch @searchParams
    if ($entries.Count -eq 0) {
        throw "Cannot read objectSid from domain NC '$DomainNamingContext'."
    }

    $sidValues = $entries[0].Attributes['objectSid']
    if (-not $sidValues) {
        throw "Domain NC '$DomainNamingContext' returned no objectSid."
    }

    [SecurityIdentifier]::new([byte[]] $sidValues[0], 0).Value
}

function New-WellKnownSidSkipSet {
    <#
    .SYNOPSIS
        Build the HashSet of SIDs that must NOT be transitively expanded.

    .DESCRIPTION
        Per plan §10. Combines the universal cross-domain SIDs (Everyone,
        Authenticated Users, SELF, CREATOR OWNER, etc.) with the
        domain-relative RIDs (-498/-513/-514/-515/-516/-521) resolved
        against the runtime domain SID. BUILTIN aliases (S-1-5-32-*) are
        not enumerated here — they're matched via prefix in
        Test-IsTerminalSid because the RIDs vary by directory.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure constructor: builds and returns an in-memory set; no external state mutated.')]
    [CmdletBinding()]
    [OutputType([HashSet[string]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $DomainSid
    )

    $universal = @(
        'S-1-1-0'   # Everyone
        'S-1-5-7'   # Anonymous Logon
        'S-1-5-11'  # Authenticated Users
        'S-1-5-2'   # Network
        'S-1-5-4'   # Interactive
        'S-1-5-9'   # Enterprise Domain Controllers
        'S-1-5-10'  # Self / Principal Self
        'S-1-3-0'   # Creator Owner
        'S-1-3-1'   # Creator Group
    )
    $domainRids = @(498, 513, 514, 515, 516, 521)

    $set = [HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $universal) {
        [void] $set.Add($s)
    }
    foreach ($rid in $domainRids) {
        [void] $set.Add("$DomainSid-$rid")
    }

    , $set
}

function Test-IsTerminalSid {
    <#
    .SYNOPSIS
        Decide whether a trustee SID should be treated as terminal — i.e.,
        emitted as itself with no group expansion.

    .DESCRIPTION
        True iff the SID is in -SkipSet (universal + domain-RID-resolved
        per plan §10) or matches the BUILTIN alias prefix S-1-5-32-*.
        Phase 6 will use this to short-circuit Expand-GroupTransitive.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Sid,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [HashSet[string]] $SkipSet
    )

    [bool] ($SkipSet.Contains($Sid) -or $Sid -like 'S-1-5-32-*')
}

function Get-DistinctTrusteeSetFromStream {
    <#
    .SYNOPSIS
        Streaming variant of Get-DistinctTrusteeSet: dedupe TrusteeSid
        values across a Phase 3 CLIXML batch file without materialising
        the whole record set in memory.

    .DESCRIPTION
        Iterates the file via Read-AceStream (defined in
        Phase3-AceParsing.ps1) and accumulates each non-empty TrusteeSid
        into a case-insensitive HashSet. Same dedupe semantics as the
        in-memory Get-DistinctTrusteeSet — drops empty / null TrusteeSid
        values (PARSE_ERROR placeholders).

        Used by the entry script in Phase 4 to enumerate trustees without
        keeping the post-Phase-3 ACE list resident. Per ADR-030, the
        in-memory $aceRecords list has been replaced with a disk-backed
        stream; this is the consumer for the distinct-trustee pass.

    .PARAMETER Phase3AceRecordsPath
        Path to the Phase 3 CLIXML batch file produced by
        Write-AceBatchToStream.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure constructor: builds and returns an in-memory set; no external state mutated.')]
    [CmdletBinding()]
    [OutputType([HashSet[string]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Phase3AceRecordsPath
    )

    $set = [HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($ace in (Read-AceStream -Path $Phase3AceRecordsPath)) {
        # Iterate so an array-shaped TrusteeSid (BUG-003) contributes each
        # element as a clean string instead of $OFS-coercing into a
        # space-joined compound key when handed to HashSet[string].Add.
        # foreach over a scalar string yields it once; over $null, zero.
        foreach ($sid in $ace.TrusteeSid) {
            if ($sid) {
                [void] $set.Add([string] $sid)
            }
        }
    }

    , $set
}

function Resolve-DomainPrincipal {
    <#
    .SYNOPSIS
        Look up an in-domain principal by SID.

    .DESCRIPTION
        Subtree search against -DomainNamingContext for
        (objectSid=<binary-escaped SID>) requesting objectClass and
        distinguishedName. Returns a record carrying the DN and the
        derived PrincipalType, or $null when not found. Used by
        Resolve-TrusteeSid to refine the PrincipalType on a SID that
        Translate already mapped to a name.
    #>
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Sid,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Connection,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $DomainNamingContext
    )

    $filter = "(objectSid=$(ConvertTo-LdapBinaryFilter -Sid $Sid))"
    $searchParams = @{
        Connection = $Connection
        SearchBase = $DomainNamingContext
        Filter     = $filter
        Attributes = @('objectClass', 'distinguishedName', 'sAMAccountName')
    }
    $entries = Invoke-PagedLdapSearch @searchParams
    if ($entries.Count -eq 0) { return }

    $entry   = $entries[0]
    $classes = if ($entry.Attributes['objectClass']) { @($entry.Attributes['objectClass']) } else { @() }
    $type    = Get-PrincipalTypeFromObjectClass -ObjectClasses $classes
    $sam     = if ($entry.Attributes['sAMAccountName']) { $entry.Attributes['sAMAccountName'][0] } else { '' }

    [PSCustomObject]@{
        DistinguishedName = $entry.DistinguishedName
        PrincipalType     = $type
        SamAccountName    = $sam
    }
}

function Resolve-ForeignSecurityPrincipal {
    <#
    .SYNOPSIS
        Look up a SID under CN=ForeignSecurityPrincipals,<domainNC>.

    .DESCRIPTION
        FSP child cn equals the SID string; a one-level search by
        (cn=<sid>) finds them without binary encoding. Returns a record
        carrying the DN, or $null when not found.
    #>
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Sid,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Connection,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $DomainNamingContext
    )

    $searchParams = @{
        Connection = $Connection
        SearchBase = "CN=ForeignSecurityPrincipals,$DomainNamingContext"
        Filter     = "(cn=$Sid)"
        Attributes = @('cn', 'distinguishedName', 'objectClass')
    }
    $entries = Invoke-PagedLdapSearch @searchParams
    if ($entries.Count -eq 0) { return }

    [PSCustomObject]@{
        DistinguishedName = $entries[0].DistinguishedName
    }
}

function Resolve-TrusteeSid {
    <#
    .SYNOPSIS
        Resolve a SID string to a categorised trustee record per plan §10.

    .DESCRIPTION
        Resolution order matches plan §5 Phase 4:
          1. Cache lookup (short-circuits all LDAP/LSA work).
          2. Resolve-NTAccount (LSA Translate).
          3. Static well-known map (Phase 1's WellKnownSidMap).
          4. ForeignSecurityPrincipals container search.
          5. Mark Orphaned.
        On a successful Translate the function additionally does an
        in-domain LDAP lookup by objectSid to refine PrincipalType from
        objectClass (User / Group / Computer / sMSA / gMSA). Builtin and
        NT AUTHORITY translations short-circuit to PrincipalType =
        'WellKnown' without an LDAP roundtrip. When Translate succeeds
        but the SID is not in the local directory, PrincipalType is
        'CrossDomain' — typically a trusted-forest or external principal.

        Always populates -Cache before emitting so subsequent calls hit
        path 1 and skip both LSA and LDAP traffic.

    .PARAMETER Sid
        SID string to resolve.

    .PARAMETER Cache
        Dictionary[string, PSObject] keyed by SID; populated as a side
        effect.

    .PARAMETER WellKnownSidMap
        Dictionary[string, string] from Phase 1's New-WellKnownSidMap.

    .PARAMETER Connection
        Bound LdapConnection (untyped for mockability — see ADR-002).

    .PARAMETER DomainNamingContext
        DN of the domain NC; used as both the in-domain search base and
        the parent of CN=ForeignSecurityPrincipals.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Mutates the supplied -Cache dictionary as the documented side effect; no external state.')]
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Sid,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [Dictionary[string, PSObject]] $Cache,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [Dictionary[string, string]] $WellKnownSidMap,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Connection,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $DomainNamingContext
    )

    $cached = $null
    if ($Cache.TryGetValue($Sid, [ref] $cached)) {
        $cached
        return
    }

    $resolved = [PSCustomObject]@{
        Sid               = $Sid
        Name              = $Sid
        PrincipalType     = 'Unknown'
        DistinguishedName = $null
    }

    $translated = $null
    try {
        $translated = Resolve-NTAccount -Sid $Sid
    }
    catch {
        $translated = $null
    }

    if ($translated) {
        $resolved.Name = $translated

        if ($translated -like 'BUILTIN\*' -or $translated -like 'NT AUTHORITY\*') {
            $resolved.PrincipalType = 'WellKnown'
        }
        else {
            $domainParams = @{
                Sid                 = $Sid
                Connection          = $Connection
                DomainNamingContext = $DomainNamingContext
            }
            $domain = Resolve-DomainPrincipal @domainParams
            if ($domain) {
                $resolved.DistinguishedName = $domain.DistinguishedName
                $resolved.PrincipalType     = $domain.PrincipalType
            }
            else {
                # Translate succeeded but the principal isn't in this domain's
                # directory — typically a trusted cross-forest/external user or
                # group whose name the local LSA can resolve. Distinct from
                # WellKnown (SYSTEM/Everyone) and Orphaned (no Translate).
                $resolved.PrincipalType = 'CrossDomain'
            }
        }
    }
    else {
        $wkName = $null
        if ($WellKnownSidMap.TryGetValue($Sid, [ref] $wkName)) {
            $resolved.Name          = $wkName
            $resolved.PrincipalType = 'WellKnown'
        }
        else {
            $fspParams = @{
                Sid                 = $Sid
                Connection          = $Connection
                DomainNamingContext = $DomainNamingContext
            }
            $fsp = Resolve-ForeignSecurityPrincipal @fspParams
            if ($fsp) {
                $resolved.DistinguishedName = $fsp.DistinguishedName
                $resolved.PrincipalType     = 'ForeignSecurityPrincipal'
            }
            else {
                $resolved.PrincipalType = 'Orphaned'
            }
        }
    }

    $Cache[$Sid] = $resolved
    $resolved
}

function Expand-GroupTransitive {
    <#
    .SYNOPSIS
        Return the transitive member set of a group via the in-chain
        matching rule, caching the result by group SID.

    .DESCRIPTION
        Filter: (memberOf:1.2.840.113556.1.4.1941:=<groupDN>) — one query
        resolves the entire transitive closure server-side, including
        nested groups, with cycle handling done by the matching-rule
        implementation. Cache hits short-circuit the LDAP roundtrip.
        -MaxMembers caps the result-set size as a defensive safety net
        against pathological group sizes (e.g., Domain Users in a
        misconfigured environment) — terminal trustees are kept out of
        the input via Test-IsTerminalSid in the caller.

        Per plan §10, well-known/skip-set trustees never reach this
        function — Phase 6 calls Test-IsTerminalSid first and emits the
        trustee as itself.

    .PARAMETER GroupSid
        SID string of the group; used as the cache key.

    .PARAMETER GroupDistinguishedName
        DN of the group for the in-chain filter. Matching-rule needs the
        DN, not the SID.

    .PARAMETER Cache
        Dictionary[string, List[PSObject]] keyed by group SID; populated
        as a side effect.

    .PARAMETER Connection
        Bound LdapConnection (untyped for mockability).

    .PARAMETER DomainNamingContext
        Search base for the in-chain query.

    .PARAMETER MaxMembers
        Defensive cap on returned member count. Default 100000 — far
        beyond any sane group size but small enough to fail loudly on
        pathological cases.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Mutates the supplied -Cache dictionary as the documented side effect; no external state.')]
    [CmdletBinding()]
    [OutputType([List[PSObject]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $GroupSid,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $GroupDistinguishedName,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [Dictionary[string, List[PSObject]]] $Cache,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Connection,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $DomainNamingContext,

        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int] $MaxMembers = 100000
    )

    $cached = $null
    if ($Cache.TryGetValue($GroupSid, [ref] $cached)) {
        , $cached
        return
    }

    $filter = "(memberOf:1.2.840.113556.1.4.1941:=$GroupDistinguishedName)"
    $searchParams = @{
        Connection       = $Connection
        SearchBase       = $DomainNamingContext
        Filter           = $filter
        Attributes       = @('objectSid', 'distinguishedName', 'objectClass', 'sAMAccountName')
        BinaryAttributes = @('objectSid')
    }
    $entries = Invoke-PagedLdapSearch @searchParams

    $members   = [List[PSObject]]::new()
    $truncated = $false
    foreach ($entry in $entries) {
        if ($members.Count -ge $MaxMembers) {
            $truncated = $true
            break
        }

        $sidValues = $entry.Attributes['objectSid']
        $memberSid = $null
        if ($sidValues) {
            $memberSid = [SecurityIdentifier]::new([byte[]] $sidValues[0], 0).Value
        }

        $classes = if ($entry.Attributes['objectClass'])    { @($entry.Attributes['objectClass']) }    else { @() }
        $sam     = if ($entry.Attributes['sAMAccountName']) { $entry.Attributes['sAMAccountName'][0] } else { '' }
        $type    = Get-PrincipalTypeFromObjectClass -ObjectClasses $classes

        $members.Add([PSCustomObject]@{
            Sid               = $memberSid
            Name              = $sam
            PrincipalType     = $type
            DistinguishedName = $entry.DistinguishedName
        })
    }

    if ($truncated) {
        Write-Warning ("Group {0} transitive expansion truncated at -MaxMembers={1}; the server returned more members. Increase -MaxMembers or scope the run if completeness matters." -f $GroupDistinguishedName, $MaxMembers)
    }

    $Cache[$GroupSid] = $members
    , $members
}
