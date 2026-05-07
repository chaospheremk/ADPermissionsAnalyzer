#Requires -Version 7.0
using namespace System.Collections.Generic
using namespace System.IO
using namespace System.Text

<#
.SYNOPSIS
    Phase 6 helpers for AD Permissions Analyzer: streaming detail CSV writer
    plus the (ACE x effective-trustee) join, RFC-4180 field escaper, and the
    incremental pivot accumulator that Step 8 will serialise.

.DESCRIPTION
    Implements §11 / §12 from docs/AD-Permissions-Analyzer-Plan.md. The detail
    CSV is written via a [StreamWriter] with manual escaping rather than
    Export-Csv — pipeline overhead at a worst-case ~5M rows would dominate
    runtime. Pivot statistics accumulate per emitted detail row into the
    supplied -PivotStats dictionary so Step 8 needs no second pass over
    $aceRecords.

    Phase 6 is the first phase whose hot loop runs once per (ACE x effective
    trustee) tuple — at the design ceiling that's ~5M iterations. The
    primitives are intentionally narrow and pure so unit tests can drive them
    from in-memory fixtures with no IO and no LDAP.

    NamingContext label for each row is derived by longest-suffix match of
    ObjectDN (upper-invariant) against the supplied NC list; the result is
    memoised per ObjectDN inside Write-DetailCsv so the cost is paid once per
    distinct object even when an object has hundreds of ACEs.
#>

# Detail CSV column order — plan §11. Single source of truth used by both
# Write-CsvHeader and ConvertTo-DetailRow so the header and per-row writes
# stay in lockstep without a second list to maintain.
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
        (no quoting). Pure helper used by ConvertTo-DetailRow once per
        column per row — keep allocation-light.
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

function ConvertTo-DetailRow {
    <#
    .SYNOPSIS
        Build one detail-CSV row as an ordered [string[]] of escaped fields.

    .DESCRIPTION
        Pure transform: takes one ACE record (post-Phase 5, with
        InheritanceSourceDN / InheritanceSourceNote populated), the
        already-resolved AceTrustee + EffectiveTrustee PSObjects (Phase 4
        cache shape: Sid, Name, PrincipalType, DistinguishedName), the
        IsThroughGroup flag and GroupExpansionPath string from
        Get-EffectiveTrusteeRecord, the NamingContext label, and the run's
        UTC ISO-8601 CollectedAt timestamp. Emits a [string[]] of escaped
        fields in plan-§11 column order — caller joins with ',' and
        WriteLine's via a StreamWriter.

        Synthetic.Owner rows pass through with AceIndex = -1 and
        RightsDecoded = 'OwnerImplicit' unchanged. PARSE_ERROR rows emit
        the captured exception message in ObjectTypeName (the placeholder
        contract from Phase 3).

    .PARAMETER Ace
        Phase 3 ACE record after Phase 5 mutation.

    .PARAMETER AceTrustee
        Resolved trustee PSObject for the ACE's TrusteeSid (Phase 4 cache).

    .PARAMETER EffectiveTrustee
        Resolved trustee PSObject for the effective trustee — equals
        $AceTrustee for direct/terminal/non-group ACEs, or one of the
        group's transitive members for expanded rows.

    .PARAMETER IsThroughGroup
        True iff the effective trustee was reached via group expansion.

    .PARAMETER GroupExpansionPath
        Group chain (currently the ACE-trustee group's name; in-chain
        matching rule loses intermediate hops). Empty for direct rows.

    .PARAMETER NamingContext
        Pre-resolved NC label — Domain / Configuration / Schema /
        DNS:<partition-DN>.

    .PARAMETER CollectedAt
        UTC ISO-8601 timestamp string for the run.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [PSObject] $Ace,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [PSObject] $AceTrustee,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [PSObject] $EffectiveTrustee,

        [Parameter(Mandatory)]
        [bool] $IsThroughGroup,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $GroupExpansionPath,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $NamingContext,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $CollectedAt
    )

    $objectTypeGuid          = if ($Ace.ObjectTypeGuid)          { [string] $Ace.ObjectTypeGuid }          else { '' }
    $inheritedObjectTypeGuid = if ($Ace.InheritedObjectTypeGuid) { [string] $Ace.InheritedObjectTypeGuid } else { '' }
    $objectGuid              = if ($Ace.ObjectGUID)              { [string] $Ace.ObjectGUID }              else { '' }

    $values = @(
        [string] $Ace.ObjectDN
        [string] $Ace.ObjectClass
        $objectGuid
        $NamingContext
        [string] $AceTrustee.Sid
        [string] $AceTrustee.Name
        [string] $AceTrustee.PrincipalType
        [string] $EffectiveTrustee.Sid
        [string] $EffectiveTrustee.Name
        [string] $EffectiveTrustee.PrincipalType
        [string] $EffectiveTrustee.DistinguishedName
        ([string] $IsThroughGroup)
        $GroupExpansionPath
        [string] $Ace.AceType
        ([string] $Ace.AceIndex)
        [string] $Ace.AccessControlType
        [string] $Ace.RightsDecoded
        ([string] $Ace.AccessMask)
        $objectTypeGuid
        [string] $Ace.ObjectTypeName
        [string] $Ace.ObjectTypeKind
        $inheritedObjectTypeGuid
        [string] $Ace.InheritedObjectTypeName
        ([string] $Ace.IsInherited)
        ([string] $Ace.IsDaclProtected)
        [string] $Ace.InheritanceSourceDN
        [string] $Ace.InheritanceSourceNote
        [string] $Ace.InheritanceFlags
        ([string] $Ace.AceFlagsRaw)
        $CollectedAt
    )

    $escaped = [string[]]::new($values.Length)
    for ($i = 0; $i -lt $values.Length; $i++) {
        $escaped[$i] = New-CsvFieldEscaper -Value $values[$i]
    }
    , $escaped
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
        dictionary so Step 8 can serialise without a second pass.

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
        Step 8's Pivot CSV writer consumes this.

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

            foreach ($tuple in $tuples) {
                $rowParams = @{
                    Ace                = $ace
                    AceTrustee         = $tuple.AceTrustee
                    EffectiveTrustee   = $tuple.EffectiveTrustee
                    IsThroughGroup     = $tuple.IsThroughGroup
                    GroupExpansionPath = $tuple.GroupExpansionPath
                    NamingContext      = $ncLabel
                    CollectedAt        = $CollectedAt
                }
                $row = ConvertTo-DetailRow @rowParams
                $writer.WriteLine([string]::Join(',', $row))

                $statParams = @{
                    Stats            = $PivotStats
                    EffectiveTrustee = $tuple.EffectiveTrustee
                    Ace              = $ace
                    IsThroughGroup   = $tuple.IsThroughGroup
                    NamingContext    = $ncLabel
                }
                Update-PivotStat @statParams

                $rowsWritten++
                if ($ProgressCallback -and ($rowsWritten % $ProgressInterval -eq 0)) {
                    $progressData = @{
                        rowsWritten = $rowsWritten
                        elapsedMs   = [int] ([DateTime]::UtcNow - $start).TotalMilliseconds
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
