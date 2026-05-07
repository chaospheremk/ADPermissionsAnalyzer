#Requires -Version 7.0
using namespace System.Collections.Generic
using namespace System.Security.AccessControl

<#
.SYNOPSIS
    Phase 5 helpers for AD Permissions Analyzer: composite-key index over
    explicit ACEs + inheritance source resolution with DACL_PROTECTED
    short-circuit.

.DESCRIPTION
    Implements §9 from docs/AD-Permissions-Analyzer-Plan.md. Pure in-memory
    transforms over the Phase 3 $aceRecords list — no IO, no LDAP. Phase 5
    is the FIRST phase that mutates $aceRecords: every row gains
    InheritanceSourceDN and InheritanceSourceNote columns so the Phase 6
    detail-CSV schema is uniform across explicit and inherited rows.

    The index keying is plan §9: (ObjectDN, TrusteeSid, AccessMask,
    ObjectTypeGuid). DN strings are normalised to upper-invariant before
    insertion AND lookup because ValueTuple<...,string,...> uses
    case-sensitive ordinal equality by default; AD DN comparison is
    case-insensitive.

    Synthetic.Owner rows (AceIndex = -1) and PARSE_ERROR placeholders
    (AceIndex = -2) are excluded from the index — they are never the
    source of an inheritance chain.

    Inheritance flags are sourced from each ACE's AceFlagsRaw byte
    (Phase 3 composes ContainerInherit / ObjectInherit / NoPropagateInherit
    / InheritOnly / Inherited bits there). The InheritanceFlags string on
    each record is the [System.Security.AccessControl.InheritanceFlags]
    enum form — useful for CSV output, but missing the propagation bits we
    need for Phase 5's class-filter rule.
#>

function New-AceIndex {
    <#
    .SYNOPSIS
        Build the composite-key inheritance index over explicit ACEs only.

    .DESCRIPTION
        Single-pass over $AceRecords. Skips inherited rows (they're the
        consumers, not the sources), Synthetic.Owner rows (AceIndex = -1;
        they are not part of the DACL inheritance graph), and PARSE_ERROR
        placeholders (AceIndex = -2). Composite-key collisions stack into
        the same List — Resolve-InheritanceSource scans the list and the
        first candidate matching Test-InheritanceFlagsPropagateTo wins.

        Returns Dictionary[ValueTuple[string, string, uint32, guid],
        List[PSObject]] keyed by (ObjectDN-upper, TrusteeSid, AccessMask,
        ObjectTypeGuid).

    .PARAMETER AceRecords
        Phase 3 output: every parsed ACE plus synthetic owner rows plus
        per-object PARSE_ERROR placeholders.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure constructor: builds and returns an in-memory dictionary; no external state mutated.')]
    [CmdletBinding()]
    [OutputType([Dictionary[ValueTuple[string, string, uint32, guid], List[PSObject]]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [List[PSObject]] $AceRecords
    )

    $index = [Dictionary[ValueTuple[string, string, uint32, guid], List[PSObject]]]::new()

    foreach ($ace in $AceRecords) {
        if ($ace.IsInherited)    { continue }
        if ($ace.AceIndex -lt 0) { continue }

        $key = [ValueTuple[string, string, uint32, guid]]::new(
            ([string] $ace.ObjectDN).ToUpperInvariant(),
            [string] $ace.TrusteeSid,
            [uint32] $ace.AccessMask,
            [guid]   $ace.ObjectTypeGuid)

        $bucket = $null
        if (-not $index.TryGetValue($key, [ref] $bucket)) {
            $bucket = [List[PSObject]]::new()
            $index[$key] = $bucket
        }
        $bucket.Add($ace)
    }

    , $index
}

function Get-ParentDistinguishedName {
    <#
    .SYNOPSIS
        Strip the leftmost RDN from a DN, returning the parent DN.

    .DESCRIPTION
        Pure DN-string parser — no dependence on the AD module's [DN] type
        (this is a standalone script). Walks the input character-by-character
        and emits the substring after the first unescaped comma. A backslash
        (`\`) escapes the next character per LDAP DN escaping rules
        (`\,` for literal comma, `\\` for literal backslash, `\HH` hex
        escapes). Returns $null when the input is the NC root (no
        unescaped comma) or empty.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $DistinguishedName
    )

    if ([string]::IsNullOrEmpty($DistinguishedName)) { return }

    $i      = 0
    $len    = $DistinguishedName.Length
    $parent = $null

    while ($i -lt $len) {
        $c = $DistinguishedName[$i]
        if ($c -eq '\') {
            # Skip the escape byte and the escaped character. Hex escapes
            # `\HH` are also handled correctly because the second hex digit
            # cannot be a comma; we only need to land past the escape.
            $i += 2
            continue
        }
        if ($c -eq ',') {
            $rest = $DistinguishedName.Substring($i + 1)
            if (-not [string]::IsNullOrEmpty($rest)) {
                $parent = $rest
            }
            break
        }
        $i++
    }

    $parent
}

function Test-IsContainerClass {
    <#
    .SYNOPSIS
        Heuristic: is a structural objectClass a container (vs a leaf) for
        the purpose of Phase 5 inheritance propagation?

    .DESCRIPTION
        InheritanceFlags split descendants into containers vs leaves
        (`ContainerInherit` vs `ObjectInherit`). AD has no flat container
        flag exposed via LDAP, but a small set of structural classes
        account for virtually all containers in a single domain. Anything
        not on this list is treated as a leaf — the bit-for-bit accurate
        alternative would walk the schema's possSuperiors chain, which is
        out of scope for v1.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $ObjectClass
    )

    $containers = @(
        'organizationalUnit'
        'container'
        'domain'
        'domainDNS'
        'builtinDomain'
        'lostAndFound'
        'configuration'
        'msDS-QuotaContainer'
        'rIDManager'
        'classStore'
        'dnsZone'
    )

    [bool] ($containers -contains $ObjectClass)
}

function Test-InheritanceFlagsPropagateTo {
    <#
    .SYNOPSIS
        Decide whether a parent DACL ACE should propagate to a given
        descendant per its AceFlags + InheritedObjectType class filter.

    .DESCRIPTION
        Pure function. Inputs are the parent ACE's `AceFlagsRaw` byte
        (Phase 3 composes ContainerInherit / ObjectInherit /
        NoPropagateInherit / InheritOnly / Inherited bits), the parent
        ACE's resolved `InheritedObjectTypeName` (empty string when the
        parent ACE has no class filter), the descendant's `ObjectClass`,
        and a `IsDirectChild` flag (true iff the descendant is the
        immediate child of the candidate ancestor — drives
        NoPropagateInherit's first-level-only halt).

        Rules implemented:
        - If neither ContainerInherit nor ObjectInherit is set, the ACE is
          not inheritable. Return false.
        - If NoPropagateInherit is set and the descendant is NOT the
          direct child, propagation halts. Return false.
        - If the descendant is a container, ContainerInherit is required;
          if it's a leaf, ObjectInherit is required.
        - If `InheritedObjectTypeName` is non-empty, the descendant's
          structural class must match it (case-insensitive) — otherwise
          the class filter excludes this descendant.

        InheritOnly does not gate descendant propagation — it controls
        whether the parent's own DACL receives the ACE, which is not
        the question Phase 5 is asking.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [byte] $AceFlagsRaw,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $InheritedObjectTypeName,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $DescendantClass,

        [Parameter(Mandatory)]
        [bool] $IsDirectChild
    )

    $flags = [AceFlags] $AceFlagsRaw

    $hasContainerInherit = $flags.HasFlag([AceFlags]::ContainerInherit)
    $hasObjectInherit    = $flags.HasFlag([AceFlags]::ObjectInherit)
    $noPropagate         = $flags.HasFlag([AceFlags]::NoPropagateInherit)

    if (-not ($hasContainerInherit -or $hasObjectInherit)) {
        $false
        return
    }

    if ($noPropagate -and -not $IsDirectChild) {
        $false
        return
    }

    $isContainer = Test-IsContainerClass -ObjectClass $DescendantClass
    if ($isContainer -and -not $hasContainerInherit) {
        $false
        return
    }
    if (-not $isContainer -and -not $hasObjectInherit) {
        $false
        return
    }

    if (-not [string]::IsNullOrEmpty($InheritedObjectTypeName)) {
        [string]::Equals(
            $InheritedObjectTypeName,
            $DescendantClass,
            [StringComparison]::OrdinalIgnoreCase)
        return
    }

    $true
}

function Resolve-InheritanceSource {
    <#
    .SYNOPSIS
        Populate InheritanceSourceDN + InheritanceSourceNote on every
        record in $AceRecords, mutating in place per plan §9.

    .DESCRIPTION
        Phase 5 entry point. For each row in $AceRecords:

        1. Add the InheritanceSourceDN and InheritanceSourceNote columns
           if they aren't already present, defaulting to $null and ''
           respectively. Explicit rows leave both empty per plan §11.
        2. If the row is not inherited (or is a Synthetic.Owner /
           PARSE_ERROR placeholder), skip.
        3. If the parent object's DACL is protected (IsDaclProtected
           = $true), record the InconsistentProtectedDacl note and emit
           an anomaly record into -ProtectedDaclAnomalies. Plan §9 calls
           this an internal-consistency violation: a protected DACL
           should have NO inherited ACEs.
        4. Otherwise walk the parent chain of the row's ObjectDN, doing
           a direct-lookup against $AceIndex at each ancestor. Stop at
           the first candidate that passes
           Test-InheritanceFlagsPropagateTo — by construction this is the
           NEAREST matching ancestor. Stop walking when we leave every
           enumerated NC.
        5. If no ancestor matches, record SchemaDefaultOrUnresolved.

        Returns a stats record with counts the entry script writes into
        the PhaseEnd JSONL event. Anomalies are emitted into the supplied
        -ProtectedDaclAnomalies list (the entry script forwards them as
        BatchError events).

    .PARAMETER AceRecords
        Phase 3 ACE list. Mutated in place — the schema gains
        InheritanceSourceDN and InheritanceSourceNote columns on every
        row.

    .PARAMETER AceIndex
        Output of New-AceIndex. Composite-key dictionary over explicit
        rows only.

    .PARAMETER NamingContextDistinguishedNames
        DN strings for every NC the run enumerated (Phase 1 output).
        Used as the stop condition for the parent-chain walk.

    .PARAMETER ProtectedDaclAnomalies
        Optional sink for plan §9 'InheritedAceOnProtectedDacl' anomaly
        records. The entry script forwards each into Write-LogEvent at
        WARN level matching the BatchError shape from Phase 3.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Mutates $AceRecords in place (plan §9 contract); does not write to disk or external state.')]
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [List[PSObject]] $AceRecords,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [Dictionary[ValueTuple[string, string, uint32, guid], List[PSObject]]] $AceIndex,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [string[]] $NamingContextDistinguishedNames,

        [Parameter()]
        [List[PSObject]] $ProtectedDaclAnomalies
    )

    $ncRoots = [List[string]]::new()
    foreach ($nc in $NamingContextDistinguishedNames) {
        if (-not [string]::IsNullOrEmpty($nc)) {
            $ncRoots.Add($nc.ToUpperInvariant())
        }
    }

    $inheritedTotal = 0
    $resolved       = 0
    $unresolved     = 0
    $protectedDacl  = 0

    foreach ($ace in $AceRecords) {
        if (-not $ace.PSObject.Properties['InheritanceSourceDN']) {
            $ace | Add-Member -NotePropertyName 'InheritanceSourceDN' -NotePropertyValue $null
        }
        if (-not $ace.PSObject.Properties['InheritanceSourceNote']) {
            $ace | Add-Member -NotePropertyName 'InheritanceSourceNote' -NotePropertyValue ''
        }

        if (-not $ace.IsInherited) { continue }
        if ($ace.AceIndex -lt 0)   { continue }

        $inheritedTotal++

        if ($ace.IsDaclProtected) {
            $ace.InheritanceSourceDN   = $null
            $ace.InheritanceSourceNote = 'InconsistentProtectedDacl'
            $protectedDacl++

            if ($null -ne $ProtectedDaclAnomalies) {
                $ProtectedDaclAnomalies.Add([PSCustomObject]@{
                    Event      = 'InheritedAceOnProtectedDacl'
                    ObjectDN   = $ace.ObjectDN
                    TrusteeSid = $ace.TrusteeSid
                    AccessMask = $ace.AccessMask
                    AceIndex   = $ace.AceIndex
                })
            }
            continue
        }

        $parent         = Get-ParentDistinguishedName -DistinguishedName $ace.ObjectDN
        $level          = 1
        $found          = $false
        $objectTypeGuid = [guid] $ace.ObjectTypeGuid
        $accessMask     = [uint32] $ace.AccessMask
        $trusteeSid     = [string] $ace.TrusteeSid
        $descendantClass = [string] $ace.ObjectClass

        while ($parent) {
            $parentUpper  = $parent.ToUpperInvariant()
            $withinAnyNc  = $false
            $isAtNcRoot   = $false
            foreach ($root in $ncRoots) {
                if ($parentUpper -eq $root) {
                    $withinAnyNc = $true
                    $isAtNcRoot  = $true
                    break
                }
                if ($parentUpper.EndsWith(",$root")) {
                    $withinAnyNc = $true
                    break
                }
            }
            if (-not $withinAnyNc) { break }

            $key = [ValueTuple[string, string, uint32, guid]]::new(
                $parentUpper, $trusteeSid, $accessMask, $objectTypeGuid)

            $candidates = $null
            if ($AceIndex.TryGetValue($key, [ref] $candidates)) {
                foreach ($candidate in $candidates) {
                    $checkParams = @{
                        AceFlagsRaw             = [byte] $candidate.AceFlagsRaw
                        InheritedObjectTypeName = [string] $candidate.InheritedObjectTypeName
                        DescendantClass         = $descendantClass
                        IsDirectChild           = ($level -eq 1)
                    }
                    if (Test-InheritanceFlagsPropagateTo @checkParams) {
                        $ace.InheritanceSourceDN   = $parent
                        $ace.InheritanceSourceNote = ''
                        $found = $true
                        break
                    }
                }
            }

            if ($found)      { break }
            if ($isAtNcRoot) { break }

            $parent = Get-ParentDistinguishedName -DistinguishedName $parent
            $level++
        }

        if ($found) {
            $resolved++
        }
        else {
            $ace.InheritanceSourceDN   = $null
            $ace.InheritanceSourceNote = 'SchemaDefaultOrUnresolved'
            $unresolved++
        }
    }

    [PSCustomObject]@{
        Indexed         = $AceIndex.Count
        InheritedTotal  = $inheritedTotal
        Resolved        = $resolved
        Unresolved      = $unresolved
        ProtectedDacl   = $protectedDacl
    }
}
