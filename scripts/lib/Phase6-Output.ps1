#Requires -Version 7.0
using namespace System.Collections.Generic
using namespace System.IO
using namespace System.Text

<#
.SYNOPSIS
    Phase 6 helpers for AD Permissions Analyzer: streaming detail CSV writer
    plus the (ACE x effective-trustee) join, RFC-4180 field escaper, the
    incremental pivot accumulator, and the pivot CSV writer.

.DESCRIPTION
    Implements §11 / §12 from docs/AD-Permissions-Analyzer-Plan.md. The detail
    CSV is written via a [StreamWriter] with manual escaping rather than
    Export-Csv — pipeline overhead at a worst-case ~5M rows would dominate
    runtime. Pivot statistics accumulate per emitted detail row into the
    supplied -PivotStats dictionary, then Write-PivotCsv consumes the
    populated dictionary directly with no second pass over $aceRecords.

    Phase 6 is the first phase whose hot loop runs once per (ACE x effective
    trustee) tuple — at the design ceiling that's ~5M iterations. The
    primitives are intentionally narrow and pure so unit tests can drive them
    from in-memory fixtures with no IO and no LDAP.

    NamingContext label for each row is derived by longest-suffix match of
    ObjectDN (upper-invariant) against the supplied NC list; the result is
    memoised per ObjectDN inside Write-DetailCsv so the cost is paid once per
    distinct object even when an object has hundreds of ACEs.
#>

# Detail CSV column order — plan §11. Single source of truth used by
# Write-CsvHeader so the header and Write-DetailCsv's inlined per-row
# write stay in lockstep. The inlined row write must keep this column
# order exactly; tests assert the shape end-to-end via Import-Csv.
$script:Phase6DetailColumns = @(
    'ObjectDN'
    'ObjectClass'
    'ObjectGUID'
    'NamingContext'
    'AceTrusteeSid'
    'AceTrusteeName'
    'AceTrusteePrincipalType'
    'EffectiveTrusteeSid'
    'EffectiveTrusteeName'
    'EffectiveTrusteePrincipalType'
    'EffectiveTrusteeDN'
    'IsThroughGroup'
    'GroupExpansionPath'
    'AceType'
    'AceIndex'
    'AccessControlType'
    'RightsDecoded'
    'AccessMask'
    'ObjectTypeGuid'
    'ObjectTypeName'
    'ObjectTypeKind'
    'InheritedObjectTypeGuid'
    'InheritedObjectTypeName'
    'IsInherited'
    'IsDaclProtected'
    'InheritanceSourceDN'
    'InheritanceSourceNote'
    'InheritanceFlags'
    'AceFlagsRaw'
    'CollectedAt'
)

function New-CsvFieldEscaper {
    <#
    .SYNOPSIS
        Escape one CSV field per RFC 4180.

    .DESCRIPTION
        Quotes the field iff it contains a comma, double-quote, CR, or LF;
        embedded double-quotes are doubled. Returns '' for $null / empty
        (no quoting). Pure helper used by Write-DetailCsv's inlined row
        builder once per column per row — keep allocation-light.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure transform: returns the escaped string; no external state mutated.')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [AllowNull()]
        [string] $Value
    )

    if ([string]::IsNullOrEmpty($Value)) { return '' }

    if ($Value.IndexOfAny([char[]] @(',', '"', "`r", "`n")) -ge 0) {
        return '"' + $Value.Replace('"', '""') + '"'
    }

    $Value
}

function Write-CsvHeader {
    <#
    .SYNOPSIS
        Write the detail CSV header line via the supplied StreamWriter.

    .DESCRIPTION
        Joins $script:Phase6DetailColumns with commas and writes one line.
        Header column names contain no escape-triggering characters by
        construction, so no per-field escape is needed.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Writes one line to the supplied StreamWriter; not an external state change.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [StreamWriter] $Writer
    )

    $Writer.WriteLine([string]::Join(',', $script:Phase6DetailColumns))
}

function Get-EffectiveTrusteeRecord {
    <#
    .SYNOPSIS
        Fan one ACE out into one or more (effective-trustee, path,
        IsThroughGroup) tuples per plan §11 / §12.

    .DESCRIPTION
        Pure single-pass join. Inputs are the ACE record, the Phase 4
        $TrusteeCache (SID -> resolved trustee), and the Phase 4
        $GroupExpansionCache (group SID -> List[PSObject] of transitive
        members). Emit policy:

          - If $GroupExpansionCache has a non-empty entry for the ACE's
            TrusteeSid, the trustee is an expandable group: emit one
            tuple per cached transitive member with IsThroughGroup = $true
            and GroupExpansionPath = the group's name (in-chain matching
            rule resolves the closure server-side, so intermediate hops
            are not visible — the path is the ACE-trustee group's name).
          - Otherwise (cache miss, terminal SID skipped by Phase 4, or an
            empty cached membership) emit a single tuple with the ACE
            trustee itself and IsThroughGroup = $false. Empty-cache
            short-circuit also covers PARSE_ERROR rows whose TrusteeSid is
            an empty string.

        Cache misses for the ACE trustee fall back to a synthetic
        PSObject carrying the raw SID — preserves visibility for ACEs
        whose trustee was not discovered during Phase 4 (e.g., an
        all-zero PARSE_ERROR row).

    .PARAMETER Ace
        Phase 3 ACE record (post-Phase 5 mutation).

    .PARAMETER TrusteeCache
        Phase 4 SID -> trustee dictionary.

    .PARAMETER GroupExpansionCache
        Phase 4 group-SID -> transitive-member list dictionary.
    #>
    [CmdletBinding()]
    [OutputType([List[PSObject]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [PSObject] $Ace,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [Dictionary[string, PSObject]] $TrusteeCache,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [Dictionary[string, List[PSObject]]] $GroupExpansionCache
    )

    $sid = [string] $Ace.TrusteeSid

    $aceTrustee = $null
    if (-not [string]::IsNullOrEmpty($sid)) {
        [void] $TrusteeCache.TryGetValue($sid, [ref] $aceTrustee)
    }
    if (-not $aceTrustee) {
        $aceTrustee = [PSCustomObject]@{
            Sid               = $sid
            Name              = $sid
            PrincipalType     = 'Unknown'
            DistinguishedName = $null
        }
    }

    $tuples = [List[PSObject]]::new()

    $expansion = $null
    $hasExpansion = $false
    if (-not [string]::IsNullOrEmpty($sid)) {
        $hasExpansion = $GroupExpansionCache.TryGetValue($sid, [ref] $expansion)
    }

    if ($hasExpansion -and $null -ne $expansion -and $expansion.Count -gt 0) {
        $groupName = if ($aceTrustee.Name) { [string] $aceTrustee.Name } else { $sid }
        foreach ($member in $expansion) {
            $tuples.Add([PSCustomObject]@{
                AceTrustee         = $aceTrustee
                EffectiveTrustee   = $member
                GroupExpansionPath = $groupName
                IsThroughGroup     = $true
            })
        }
    }
    else {
        $tuples.Add([PSCustomObject]@{
            AceTrustee         = $aceTrustee
            EffectiveTrustee   = $aceTrustee
            GroupExpansionPath = ''
            IsThroughGroup     = $false
        })
    }

    , $tuples
}

function Resolve-NamingContextLabel {
    <#
    .SYNOPSIS
        Map an ObjectDN to its NamingContext label (Domain / Configuration
        / Schema / DNS:<DN>) by longest-suffix match.

    .DESCRIPTION
        Internal helper for Write-DetailCsv. NCs may be nested
        (Schema NC sits inside Configuration NC), so longest-suffix wins.
        The match list is precomputed once per Write-DetailCsv call,
        sorted by descending DN length, with a memoisation cache keyed by
        upper-invariant ObjectDN.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $ObjectDN,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [object[]] $SortedNamingContexts,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [Dictionary[string, string]] $Cache
    )

    if ([string]::IsNullOrEmpty($ObjectDN)) { return '' }

    $upper = $ObjectDN.ToUpperInvariant()
    $cached = $null
    if ($Cache.TryGetValue($upper, [ref] $cached)) { return $cached }

    $label = ''
    foreach ($nc in $SortedNamingContexts) {
        $ncDn = $nc.DistinguishedNameUpper
        if ($upper -eq $ncDn -or $upper.EndsWith(",$ncDn")) {
            $label = if ($nc.Type -eq 'DNS') { "DNS:$($nc.DistinguishedName)" } else { [string] $nc.Type }
            break
        }
    }

    $Cache[$upper] = $label
    $label
}

function Update-PivotStat {
    <#
    .SYNOPSIS
        Increment one effective-trustee bucket in -PivotStats per emitted
        detail row.

    .DESCRIPTION
        Internal helper for Write-DetailCsv. First emission per trustee
        seeds the bucket with descriptive fields (Name, PrincipalType,
        DN); subsequent emissions only update counters. Pure mutation
        with no IO.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Mutates the supplied -Stats dictionary as the documented side effect.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [Dictionary[string, PSObject]] $Stats,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [PSObject] $EffectiveTrustee,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [PSObject] $Ace,

        [Parameter(Mandatory)]
        [bool] $IsThroughGroup,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $NamingContext
    )

    $sid = [string] $EffectiveTrustee.Sid
    if ([string]::IsNullOrEmpty($sid)) { $sid = '<empty>' }

    $bucket = $null
    if (-not $Stats.TryGetValue($sid, [ref] $bucket)) {
        $bucket = [PSCustomObject]@{
            EffectiveTrusteeSid           = $sid
            EffectiveTrusteeName          = [string] $EffectiveTrustee.Name
            EffectiveTrusteePrincipalType = [string] $EffectiveTrustee.PrincipalType
            EffectiveTrusteeDN            = [string] $EffectiveTrustee.DistinguishedName
            TotalAceCount                 = 0
            DirectAceCount                = 0
            IndirectAceCount              = 0
            DistinctObjectDns             = [HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            AllowAceCount                 = 0
            DenyAceCount                  = 0
            ExplicitAceCount              = 0
            InheritedAceCount             = 0
            RightsBreakdown               = [Dictionary[string, int]]::new([System.StringComparer]::OrdinalIgnoreCase)
            NamingContextsTouched         = [HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            ObjectClassesTouched          = [Dictionary[string, int]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }
        $Stats[$sid] = $bucket
    }

    $bucket.TotalAceCount++
    if ($IsThroughGroup) { $bucket.IndirectAceCount++ } else { $bucket.DirectAceCount++ }

    if ($Ace.AccessControlType -eq 'Allow') { $bucket.AllowAceCount++ }
    elseif ($Ace.AccessControlType -eq 'Deny') { $bucket.DenyAceCount++ }

    if ($Ace.IsInherited) { $bucket.InheritedAceCount++ } else { $bucket.ExplicitAceCount++ }

    $objectDn = [string] $Ace.ObjectDN
    if (-not [string]::IsNullOrEmpty($objectDn)) {
        [void] $bucket.DistinctObjectDns.Add($objectDn)
    }

    if (-not [string]::IsNullOrEmpty($NamingContext)) {
        [void] $bucket.NamingContextsTouched.Add($NamingContext)
    }

    $cls = [string] $Ace.ObjectClass
    if (-not [string]::IsNullOrEmpty($cls)) {
        $current = 0
        [void] $bucket.ObjectClassesTouched.TryGetValue($cls, [ref] $current)
        $bucket.ObjectClassesTouched[$cls] = $current + 1
    }

    $rightsString = [string] $Ace.RightsDecoded
    if (-not [string]::IsNullOrEmpty($rightsString)) {
        foreach ($r in $rightsString.Split(',')) {
            $right = $r.Trim()
            if ([string]::IsNullOrEmpty($right)) { continue }
            $current = 0
            [void] $bucket.RightsBreakdown.TryGetValue($right, [ref] $current)
            $bucket.RightsBreakdown[$right] = $current + 1
        }
    }
}

function Write-DetailCsv {
    <#
    .SYNOPSIS
        Stream the detail CSV per plan §11 / §12 and incrementally build
        the pivot accumulator.

    .DESCRIPTION
        Opens a [StreamWriter] at -DetailPath (UTF-8, no BOM, AutoFlush
        off — flushes once at end). Writes the header, then for each ACE
        in -AceRecords expands into one or more (effective trustee, path,
        IsThroughGroup) tuples via Get-EffectiveTrusteeRecord and writes
        one row per tuple. Each emitted tuple updates the -PivotStats
        dictionary so Write-PivotCsv can serialise without a second pass.

        -ProgressCallback (optional scriptblock) fires every
        -ProgressInterval rows with the running tuple count + elapsed ms;
        the entry script wires this to Write-LogEvent so the lib stays
        free of logging coupling (matches the Phase 4 / Phase 5 boundary
        pattern).

        Returns an [int] of detail rows written. The pivot bucket count
        equals the number of distinct effective trustees that appeared.

    .PARAMETER DetailPath
        Absolute path to the detail CSV file.

    .PARAMETER AceRecords
        Phase 3 ACE list, post-Phase 5 mutation
        (InheritanceSourceDN / InheritanceSourceNote present on every
        row).

    .PARAMETER TrusteeCache
        Phase 4 SID -> resolved trustee dictionary.

    .PARAMETER GroupExpansionCache
        Phase 4 group-SID -> transitive-member list dictionary.

    .PARAMETER NamingContexts
        Phase 1 NC list (PSObject with DistinguishedName + Type).

    .PARAMETER PivotStats
        Mutable dictionary the function populates as a side effect.
        Write-PivotCsv consumes this directly with no second pass over
        -AceRecords.

    .PARAMETER CollectedAt
        UTC ISO-8601 timestamp string for the run.

    .PARAMETER ProgressInterval
        Emit a progress callback every N tuples (detail rows). Default
        50000.

    .PARAMETER ProgressCallback
        Optional scriptblock invoked with a [hashtable] argument carrying
        rowsWritten + elapsedMs every -ProgressInterval rows. Lets the
        entry script forward to Write-LogEvent without making the lib
        depend on it.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Writes one CSV file and mutates the supplied -PivotStats dictionary; both are documented outputs.')]
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $DetailPath,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [List[PSObject]] $AceRecords,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [Dictionary[string, PSObject]] $TrusteeCache,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [Dictionary[string, List[PSObject]]] $GroupExpansionCache,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [object[]] $NamingContexts,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [Dictionary[string, PSObject]] $PivotStats,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $CollectedAt,

        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int] $ProgressInterval = 50000,

        [Parameter()]
        [scriptblock] $ProgressCallback
    )

    # Sort NCs longest-DN first so a Schema-NC ObjectDN matches Schema rather
    # than Configuration. Wrap each entry with a precomputed upper-invariant
    # DN so the hot loop avoids re-allocating that string per row.
    $sortedNcs = [List[PSObject]]::new()
    foreach ($nc in $NamingContexts) {
        if (-not $nc.DistinguishedName) { continue }
        $sortedNcs.Add([PSCustomObject]@{
            DistinguishedName      = [string] $nc.DistinguishedName
            DistinguishedNameUpper = ([string] $nc.DistinguishedName).ToUpperInvariant()
            Type                   = [string] $nc.Type
        })
    }
    $sortedArray = ($sortedNcs.ToArray() | Sort-Object -Property { $_.DistinguishedNameUpper.Length } -Descending)

    $ncLabelCache = [Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $writer = [StreamWriter]::new($DetailPath, $false, [UTF8Encoding]::new($false))
    $writer.AutoFlush = $false

    $rowsWritten = 0
    $start = [DateTime]::UtcNow

    try {
        Write-CsvHeader -Writer $writer

        # Row builder reuses one [string[]] per iteration. CollectedAt is
        # constant for the run, so escape it once. Per-ACE invariant fields
        # are escaped once per ACE and reused across all (effective-trustee)
        # tuples — group expansion can fan one ACE into many rows.
        $row = [string[]]::new($script:Phase6DetailColumns.Length)
        $escCollectedAt = New-CsvFieldEscaper -Value $CollectedAt

        foreach ($ace in $AceRecords) {
            $ncLabelParams = @{
                ObjectDN             = [string] $ace.ObjectDN
                SortedNamingContexts = $sortedArray
                Cache                = $ncLabelCache
            }
            $ncLabel = Resolve-NamingContextLabel @ncLabelParams

            $tupleParams = @{
                Ace                 = $ace
                TrusteeCache        = $TrusteeCache
                GroupExpansionCache = $GroupExpansionCache
            }
            $tuples = Get-EffectiveTrusteeRecord @tupleParams

            $aceObjectGuidStr  = if ($ace.ObjectGUID)              { [string] $ace.ObjectGUID }              else { '' }
            $aceObjTypeGuidStr = if ($ace.ObjectTypeGuid)          { [string] $ace.ObjectTypeGuid }          else { '' }
            $aceInhObjGuidStr  = if ($ace.InheritedObjectTypeGuid) { [string] $ace.InheritedObjectTypeGuid } else { '' }

            $escObjectDN              = New-CsvFieldEscaper -Value ([string] $ace.ObjectDN)
            $escObjectClass           = New-CsvFieldEscaper -Value ([string] $ace.ObjectClass)
            $escObjectGuid            = New-CsvFieldEscaper -Value $aceObjectGuidStr
            $escNcLabel               = New-CsvFieldEscaper -Value $ncLabel
            $escAceType               = New-CsvFieldEscaper -Value ([string] $ace.AceType)
            $escAceIndex              = New-CsvFieldEscaper -Value ([string] $ace.AceIndex)
            $escAccessControlType     = New-CsvFieldEscaper -Value ([string] $ace.AccessControlType)
            $escRightsDecoded         = New-CsvFieldEscaper -Value ([string] $ace.RightsDecoded)
            $escAccessMask            = New-CsvFieldEscaper -Value ([string] $ace.AccessMask)
            $escObjectTypeGuid        = New-CsvFieldEscaper -Value $aceObjTypeGuidStr
            $escObjectTypeName        = New-CsvFieldEscaper -Value ([string] $ace.ObjectTypeName)
            $escObjectTypeKind        = New-CsvFieldEscaper -Value ([string] $ace.ObjectTypeKind)
            $escInheritedObjTypeGuid  = New-CsvFieldEscaper -Value $aceInhObjGuidStr
            $escInheritedObjTypeName  = New-CsvFieldEscaper -Value ([string] $ace.InheritedObjectTypeName)
            $escIsInherited           = New-CsvFieldEscaper -Value ([string] $ace.IsInherited)
            $escIsDaclProtected       = New-CsvFieldEscaper -Value ([string] $ace.IsDaclProtected)
            $escInheritanceSourceDN   = New-CsvFieldEscaper -Value ([string] $ace.InheritanceSourceDN)
            $escInheritanceSourceNote = New-CsvFieldEscaper -Value ([string] $ace.InheritanceSourceNote)
            $escInheritanceFlags      = New-CsvFieldEscaper -Value ([string] $ace.InheritanceFlags)
            $escAceFlagsRaw           = New-CsvFieldEscaper -Value ([string] $ace.AceFlagsRaw)

            foreach ($tuple in $tuples) {
                $aceTrustee       = $tuple.AceTrustee
                $effectiveTrustee = $tuple.EffectiveTrustee

                $row[0]  = $escObjectDN
                $row[1]  = $escObjectClass
                $row[2]  = $escObjectGuid
                $row[3]  = $escNcLabel
                $row[4]  = New-CsvFieldEscaper -Value ([string] $aceTrustee.Sid)
                $row[5]  = New-CsvFieldEscaper -Value ([string] $aceTrustee.Name)
                $row[6]  = New-CsvFieldEscaper -Value ([string] $aceTrustee.PrincipalType)
                $row[7]  = New-CsvFieldEscaper -Value ([string] $effectiveTrustee.Sid)
                $row[8]  = New-CsvFieldEscaper -Value ([string] $effectiveTrustee.Name)
                $row[9]  = New-CsvFieldEscaper -Value ([string] $effectiveTrustee.PrincipalType)
                $row[10] = New-CsvFieldEscaper -Value ([string] $effectiveTrustee.DistinguishedName)
                $row[11] = New-CsvFieldEscaper -Value ([string] $tuple.IsThroughGroup)
                $row[12] = New-CsvFieldEscaper -Value ([string] $tuple.GroupExpansionPath)
                $row[13] = $escAceType
                $row[14] = $escAceIndex
                $row[15] = $escAccessControlType
                $row[16] = $escRightsDecoded
                $row[17] = $escAccessMask
                $row[18] = $escObjectTypeGuid
                $row[19] = $escObjectTypeName
                $row[20] = $escObjectTypeKind
                $row[21] = $escInheritedObjTypeGuid
                $row[22] = $escInheritedObjTypeName
                $row[23] = $escIsInherited
                $row[24] = $escIsDaclProtected
                $row[25] = $escInheritanceSourceDN
                $row[26] = $escInheritanceSourceNote
                $row[27] = $escInheritanceFlags
                $row[28] = $escAceFlagsRaw
                $row[29] = $escCollectedAt
                $writer.WriteLine([string]::Join(',', $row))

                $statParams = @{
                    Stats            = $PivotStats
                    EffectiveTrustee = $effectiveTrustee
                    Ace              = $ace
                    IsThroughGroup   = $tuple.IsThroughGroup
                    NamingContext    = $ncLabel
                }
                Update-PivotStat @statParams

                $rowsWritten++
                if ($ProgressCallback -and ($rowsWritten % $ProgressInterval -eq 0)) {
                    $progressData = @{
                        rowsWritten = $rowsWritten
                        elapsedMs   = [long] ([DateTime]::UtcNow - $start).TotalMilliseconds
                    }
                    & $ProgressCallback $progressData
                }
            }
        }

        $writer.Flush()
    }
    finally {
        $writer.Dispose()
    }

    $rowsWritten
}

# Pivot CSV column order — plan §11. Single source of truth for
# Write-PivotCsv's header and ConvertTo-PivotRow's body.
$script:Phase6PivotColumns = @(
    'EffectiveTrusteeSid'
    'EffectiveTrusteeName'
    'EffectiveTrusteePrincipalType'
    'EffectiveTrusteeDN'
    'TotalAceCount'
    'DirectAceCount'
    'IndirectAceCount'
    'DistinctObjectCount'
    'AllowAceCount'
    'DenyAceCount'
    'ExplicitAceCount'
    'InheritedAceCount'
    'RightsSummary'
    'NamingContextsTouched'
    'ObjectClassesTouched'
    'CollectedAt'
)

function Format-RightsSummary {
    <#
    .SYNOPSIS
        Render the RightsBreakdown bucket as the plan §11 summary string
        ("GenericAll:42; WriteProperty:118; ReadProperty:980").

    .DESCRIPTION
        Pure helper. Sort order: count descending, then name ascending
        (ordinal-ignore-case) as tiebreaker so equal-count rights have a
        stable, readable order. Empty / null dictionary returns ''.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [Dictionary[string, int]] $Breakdown
    )

    if ($null -eq $Breakdown -or $Breakdown.Count -eq 0) { return '' }

    $entries = [List[PSObject]]::new()
    foreach ($kvp in $Breakdown.GetEnumerator()) {
        $entries.Add([PSCustomObject]@{ Name = $kvp.Key; Count = $kvp.Value })
    }
    $sorted = $entries.ToArray() |
        Sort-Object -Property @{ Expression = 'Count'; Descending = $true },
                              @{ Expression = 'Name';  Descending = $false }

    $parts = [List[string]]::new()
    foreach ($e in $sorted) {
        $parts.Add("$($e.Name):$($e.Count)")
    }
    [string]::Join('; ', $parts)
}

function Format-NamingContextsTouched {
    <#
    .SYNOPSIS
        Render the NamingContextsTouched HashSet as a sorted
        semicolon-delimited string.

    .DESCRIPTION
        Pure helper. Sort order: ordinal-ignore-case ascending. Empty /
        null set returns ''. Parameter is typed [object] rather than
        [HashSet[string]] because the PowerShell parameter binder
        unrolls a typed HashSet[string] argument — it converts to a
        string[] via the IEnumerable surface and either rejects an empty
        set or rebinds a singleton as a bare string. Accepting [object]
        preserves the HashSet reference; .Count and foreach still work.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $NamingContexts
    )

    if ($null -eq $NamingContexts) { return '' }

    $items = [List[string]]::new()
    foreach ($nc in $NamingContexts) {
        if ([string]::IsNullOrEmpty($nc)) { continue }
        $items.Add([string] $nc)
    }
    if ($items.Count -eq 0) { return '' }

    $sorted = $items.ToArray() | Sort-Object -CaseSensitive:$false
    [string]::Join(';', $sorted)
}

function Format-ObjectClassesTouched {
    <#
    .SYNOPSIS
        Render the ObjectClassesTouched bucket as the plan §11
        "user:14; group:3; organizationalUnit:1" summary string.

    .DESCRIPTION
        Pure helper. Sort order: count descending, then name ascending
        (ordinal-ignore-case) as tiebreaker — same convention as
        Format-RightsSummary. Empty / null dictionary returns ''.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [Dictionary[string, int]] $Classes
    )

    if ($null -eq $Classes -or $Classes.Count -eq 0) { return '' }

    $entries = [List[PSObject]]::new()
    foreach ($kvp in $Classes.GetEnumerator()) {
        $entries.Add([PSCustomObject]@{ Name = $kvp.Key; Count = $kvp.Value })
    }
    $sorted = $entries.ToArray() |
        Sort-Object -Property @{ Expression = 'Count'; Descending = $true },
                              @{ Expression = 'Name';  Descending = $false }

    $parts = [List[string]]::new()
    foreach ($e in $sorted) {
        $parts.Add("$($e.Name):$($e.Count)")
    }
    [string]::Join('; ', $parts)
}

function ConvertTo-PivotRow {
    <#
    .SYNOPSIS
        Build one pivot-CSV row as an ordered [string[]] of escaped
        fields per plan §11.

    .DESCRIPTION
        Pure transform: takes one PivotStats bucket (the PSObject seeded
        by Update-PivotStat during detail streaming) plus the run's
        CollectedAt timestamp, returns a [string[]] of RFC-4180-escaped
        fields in pivot-column order. Caller joins with ',' and writes
        via the StreamWriter.

    .PARAMETER Bucket
        Pivot accumulator entry (the PSCustomObject populated by
        Update-PivotStat during Write-DetailCsv).

    .PARAMETER CollectedAt
        UTC ISO-8601 timestamp string for the run.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [PSObject] $Bucket,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $CollectedAt
    )

    $rightsSummary       = Format-RightsSummary       -Breakdown      $Bucket.RightsBreakdown
    $namingContextsTouch = Format-NamingContextsTouched -NamingContexts $Bucket.NamingContextsTouched
    $objectClassesTouch  = Format-ObjectClassesTouched -Classes        $Bucket.ObjectClassesTouched

    $values = @(
        [string] $Bucket.EffectiveTrusteeSid
        [string] $Bucket.EffectiveTrusteeName
        [string] $Bucket.EffectiveTrusteePrincipalType
        [string] $Bucket.EffectiveTrusteeDN
        ([string] $Bucket.TotalAceCount)
        ([string] $Bucket.DirectAceCount)
        ([string] $Bucket.IndirectAceCount)
        ([string] $Bucket.DistinctObjectDns.Count)
        ([string] $Bucket.AllowAceCount)
        ([string] $Bucket.DenyAceCount)
        ([string] $Bucket.ExplicitAceCount)
        ([string] $Bucket.InheritedAceCount)
        $rightsSummary
        $namingContextsTouch
        $objectClassesTouch
        $CollectedAt
    )

    $escaped = [string[]]::new($values.Length)
    for ($i = 0; $i -lt $values.Length; $i++) {
        $escaped[$i] = New-CsvFieldEscaper -Value $values[$i]
    }
    , $escaped
}

function Write-PivotCsv {
    <#
    .SYNOPSIS
        Write the per-trustee pivot CSV from the $PivotStats accumulator
        per plan §11 / §12.

    .DESCRIPTION
        Opens a [StreamWriter] at -PivotPath (UTF-8, no BOM, AutoFlush
        off — flushes once at end; same buffering contract as
        Write-DetailCsv per ADR-018). Writes the header from
        $script:Phase6PivotColumns, then one row per bucket via
        ConvertTo-PivotRow.

        Bucket order: TotalAceCount descending, EffectiveTrusteeName
        ascending, EffectiveTrusteeSid ascending — most-active trustees
        first to surface high-value rows for least-privilege review.

        Returns an [int] of pivot rows written (one per distinct
        effective trustee that emitted at least one detail row).

    .PARAMETER PivotPath
        Absolute path to the pivot CSV file.

    .PARAMETER Stats
        Phase 6 pivot accumulator populated by Write-DetailCsv (one
        bucket per EffectiveTrusteeSid).

    .PARAMETER CollectedAt
        UTC ISO-8601 timestamp string for the run.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Writes one CSV file; the side effect is the documented output.')]
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $PivotPath,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [Dictionary[string, PSObject]] $Stats,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $CollectedAt
    )

    # ADR-018 (amended): pivot CSV ships with a UTF-8 BOM so Excel on Windows
    # renders non-ASCII DN/trustee values correctly without a manual import.
    # The detail CSV remains BOM-less for batch consumers (pandas/Power BI/SIEM).
    $writer = [StreamWriter]::new($PivotPath, $false, [UTF8Encoding]::new($true))
    $writer.AutoFlush = $false

    $rowsWritten = 0
    try {
        $writer.WriteLine([string]::Join(',', $script:Phase6PivotColumns))

        $buckets = [List[PSObject]]::new()
        foreach ($kvp in $Stats.GetEnumerator()) {
            $buckets.Add($kvp.Value)
        }
        $ordered = $buckets.ToArray() |
            Sort-Object -Property @{ Expression = 'TotalAceCount';        Descending = $true  },
                                  @{ Expression = 'EffectiveTrusteeName'; Descending = $false },
                                  @{ Expression = 'EffectiveTrusteeSid';  Descending = $false }

        foreach ($bucket in $ordered) {
            $row = ConvertTo-PivotRow -Bucket $bucket -CollectedAt $CollectedAt
            $writer.WriteLine([string]::Join(',', $row))
            $rowsWritten++
        }

        $writer.Flush()
    }
    finally {
        $writer.Dispose()
    }

    $rowsWritten
}
