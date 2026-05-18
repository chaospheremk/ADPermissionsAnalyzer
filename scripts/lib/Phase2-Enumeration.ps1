#Requires -Version 7.0
using namespace System.Collections.Generic

# SDP types use fully-qualified names — see Phase1-DiscoveryAndMaps.ps1 header
# and docs/session-changes-2025-05-15.md §1.

<#
.SYNOPSIS
    Phase 2 helper for AD Permissions Analyzer: paged enumeration of every
    object in a naming context together with its raw nTSecurityDescriptor.

.DESCRIPTION
    Implements §5 Phase 2 from docs/AD-Permissions-Analyzer-Plan.md. Builds on
    Read-LdapEntry (Phase1-DiscoveryAndMaps.ps1) so the page loop and
    binary-attribute extraction are shared; this file adds the
    SecurityDescriptorFlagControl(OWNER | DACL) and the batch-yield contract
    Phase 3 will consume.
#>

function Get-ADObjectAclBatch {
    <#
    .SYNOPSIS
        Stream batches of objects-with-SD from a naming context to the pipeline.

    .DESCRIPTION
        Runs a paged subtree search over -SearchBase requesting
        distinguishedName, structuralObjectClass (with objectClass last-value
        as fallback), objectGUID, and nTSecurityDescriptor. Attaches
        SecurityDescriptorFlagControl(OWNER | DACL) so the server returns the
        owner and DACL portions of nTSecurityDescriptor without requiring
        SeSecurityPrivilege (SACL is explicitly out of scope per plan §1).

        Each batch is a [List[PSObject]] of up to -BatchSize objects, written
        to the pipeline with no enumeration so the consumer's foreach receives
        whole batches. Yielding rather than materialising the full result set
        is the §6/§12 memory-hygiene contract — Phase 3 will consume each
        batch as it arrives instead of holding all 30k SDs in memory.

        Empty result sets short-circuit naturally: zero entries from
        Read-LdapEntry means the function emits nothing, so the consumer's
        foreach iterates zero times.

    .PARAMETER Connection
        Already-bound LdapConnection (typing relaxed for mockability).

    .PARAMETER SearchBase
        DN of the naming context to enumerate.

    .PARAMETER BatchSize
        Maximum object count per emitted batch. Default 250 (matches the
        Phase 3 runspace work-unit size).

    .PARAMETER PageSize
        LDAP server-side page size for the underlying search. Default 1000
        (the AD cap). Independent of -BatchSize: one LDAP page typically
        produces several batches.
    #>
    [CmdletBinding()]
    [OutputType([List[PSObject]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Connection,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $SearchBase,

        [Parameter()]
        [ValidateRange(1, 10000)]
        [int] $BatchSize = 250,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int] $PageSize = 1000
    )

    $sdMasks   = [System.DirectoryServices.Protocols.SecurityMasks]::Owner -bor [System.DirectoryServices.Protocols.SecurityMasks]::Dacl
    $sdControl = [System.DirectoryServices.Protocols.SecurityDescriptorFlagControl]::new($sdMasks)

    $searchParams = @{
        Connection         = $Connection
        SearchBase         = $SearchBase
        Filter             = '(objectClass=*)'
        Attributes         = @(
            'distinguishedName'
            'structuralObjectClass'
            'objectClass'
            'objectGUID'
            'nTSecurityDescriptor'
        )
        BinaryAttributes   = @('objectGUID', 'nTSecurityDescriptor')
        AdditionalControls = , $sdControl
        PageSize           = $PageSize
        Scope              = [System.DirectoryServices.Protocols.SearchScope]::Subtree
    }

    $batch = [List[PSObject]]::new($BatchSize)

    foreach ($entry in (Read-LdapEntry @searchParams)) {
        $attrs = $entry.Attributes

        $structural = if ($attrs['structuralObjectClass']) {
            $attrs['structuralObjectClass'][0]
        }
        elseif ($attrs['objectClass']) {
            $oc = $attrs['objectClass']
            $oc[$oc.Count - 1]
        }
        else {
            ''
        }

        $guidValues = $attrs['objectGUID']
        $objectGuid = if ($guidValues) {
            [guid]::new([byte[]] $guidValues[0])
        }
        else {
            [guid]::Empty
        }

        # Explicit assignment, not if-as-expression: an if-expression unrolls
        # IEnumerable results, which would convert byte[] to Object[] of bytes.
        $sdValues = $attrs['nTSecurityDescriptor']
        $sdBytes  = $null
        if ($sdValues) {
            $sdBytes = [byte[]] $sdValues[0]
        }

        $obj = [PSCustomObject]@{
            DistinguishedName     = $entry.DistinguishedName
            StructuralObjectClass = $structural
            ObjectGUID            = $objectGuid
            NTSecurityDescriptor  = $sdBytes
        }
        $batch.Add($obj)

        if ($batch.Count -ge $BatchSize) {
            , $batch
            $batch = [List[PSObject]]::new($BatchSize)
        }
    }

    if ($batch.Count -gt 0) {
        , $batch
    }
}
