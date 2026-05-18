#Requires -Version 7.0
using namespace System.Collections.Generic
using namespace System.DirectoryServices
using namespace System.Management.Automation.Runspaces
using namespace System.Security.AccessControl
using namespace System.Security.Principal

<#
.SYNOPSIS
    Phase 3 helpers for AD Permissions Analyzer: nTSecurityDescriptor parsing,
    ACE record decoding, and the runspace-pool dispatcher.

.DESCRIPTION
    Implements §5 Phase 3, §7 ACE Decoding Rules, and the parallelism
    primitives sketched in §12 from docs/AD-Permissions-Analyzer-Plan.md.

    Functions are dot-sourced by the entry-point script
    Invoke-ADPermissionAnalysis.ps1 and exercised in isolation by the
    matching Pester suite under Tests/. The IO boundary is the SD byte[]
    itself — every function takes plain inputs (byte[] plus pre-built map
    dictionaries) so unit tests can construct fixtures via the public
    System.DirectoryServices APIs without touching a live DC.

    Inside a runspace pool the entry script wires this file as a startup
    script via InitialSessionState, which preserves the `using namespace`
    directives above. SessionStateFunctionEntry would strip them and break
    short type names — see ADR-006.
#>

function ConvertFrom-NtSecurityDescriptor {
    <#
    .SYNOPSIS
        Parse a raw nTSecurityDescriptor byte[] into Owner, DACL, and the
        SE_DACL_PROTECTED flag.

    .DESCRIPTION
        Builds an [ActiveDirectorySecurity] from the supplied binary form and
        returns a record carrying the owner SID, the parsed DACL container
        (so Phase 3 can call GetAccessRules on it), and the
        AreAccessRulesProtected boolean (which surfaces the SE_DACL_PROTECTED
        control bit). Throws on parse failure — Invoke-AceParsingWorkUnit
        catches and emits a placeholder per plan §14.

    .PARAMETER BinaryForm
        Raw nTSecurityDescriptor bytes as returned by Phase 2's
        Get-ADObjectAclBatch.
    #>
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [byte[]] $BinaryForm
    )

    $sd = [ActiveDirectorySecurity]::new()
    $sd.SetSecurityDescriptorBinaryForm($BinaryForm)

    [PSCustomObject]@{
        Owner           = $sd.GetOwner([SecurityIdentifier])
        Dacl            = $sd
        IsDaclProtected = $sd.AreAccessRulesProtected
    }
}

function Add-OwnerAce {
    <#
    .SYNOPSIS
        Emit the synthetic 'Synthetic.Owner' ACE record for a parsed object.

    .DESCRIPTION
        Per plan §5: every object gets exactly one synthetic owner row
        regardless of DACL contents. AceIndex = -1 distinguishes it from real
        DACL ACEs (which start at 0). RightsDecoded = 'OwnerImplicit' and
        AccessMask = (ReadControl | WriteDacl | WriteOwner) reflect the
        owner's standing implicit access regardless of DACL.

        Returns a single PSObject — same shape as ConvertFrom-AdAce so Phase 6
        writers can treat owner rows and DACL rows uniformly.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure constructor: emits a synthetic record; no state mutated.')]
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [SecurityIdentifier] $OwnerSid,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ObjectDN,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $ObjectClass,

        [Parameter(Mandatory)]
        [guid] $ObjectGUID,

        [Parameter(Mandatory)]
        [bool] $IsDaclProtected
    )

    $ownerMask = [int]([ActiveDirectoryRights]::ReadControl) -bor
                 [int]([ActiveDirectoryRights]::WriteDacl)   -bor
                 [int]([ActiveDirectoryRights]::WriteOwner)

    [PSCustomObject]@{
        ObjectDN                = $ObjectDN
        ObjectClass             = $ObjectClass
        ObjectGUID              = $ObjectGUID
        TrusteeSid              = $OwnerSid.Value
        AccessMask              = [uint32] $ownerMask
        AccessControlType       = 'Allow'
        AceType                 = 'Synthetic.Owner'
        RightsDecoded           = 'OwnerImplicit'
        ObjectTypeGuid          = [guid]::Empty
        ObjectTypeName          = ''
        ObjectTypeKind          = 'All'
        InheritedObjectTypeGuid = [guid]::Empty
        InheritedObjectTypeName = ''
        InheritanceFlags        = 'None'
        IsInherited             = $false
        IsDaclProtected         = $IsDaclProtected
        AceIndex                = -1
        AceFlagsRaw             = [byte] 0
    }
}

function ConvertFrom-AdAce {
    <#
    .SYNOPSIS
        Decode one ActiveDirectoryAccessRule into a flat ACE record per
        plan §5/§7/§11.

    .DESCRIPTION
        Resolves the rule's ObjectType GUID via the three GUID maps to
        produce ObjectTypeName + ObjectTypeKind (Property / PropertySet /
        ExtendedRight / ValidatedWrite / ClassChild / All / Unresolved).
        Resolves InheritedObjectType via SchemaGuidMap (classSchema only).
        Composes AceFlagsRaw from inheritance + propagation + IsInherited
        bits matching the canonical [AceFlags] mapping.

    .PARAMETER Rule
        Single ActiveDirectoryAccessRule; the IdentityReference must already
        be a SecurityIdentifier (caller passes [SecurityIdentifier] as the
        target type to GetAccessRules).

    .PARAMETER AceIndex
        0-based ordinal of this rule within the source DACL.

    .PARAMETER ObjectDN
        Distinguished name of the parent object whose DACL contained the rule.

    .PARAMETER ObjectClass
        structuralObjectClass of the parent object (objectClass last-value
        fallback already applied by Phase 2).

    .PARAMETER ObjectGUID
        objectGUID of the parent object.

    .PARAMETER IsDaclProtected
        AreAccessRulesProtected flag of the parent SD (SE_DACL_PROTECTED).

    .PARAMETER ExtendedRightsMap
        rightsGuid -> control-access-right map (ExtendedRight, ValidatedWrite,
        PropertySet) from Phase 1.

    .PARAMETER SchemaGuidMap
        schemaIDGUID -> attribute/class map from Phase 1.
    #>
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [ActiveDirectoryAccessRule] $Rule,

        [Parameter(Mandatory)]
        [int] $AceIndex,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ObjectDN,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $ObjectClass,

        [Parameter(Mandatory)]
        [guid] $ObjectGUID,

        [Parameter(Mandatory)]
        [bool] $IsDaclProtected,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [Dictionary[guid, PSObject]] $ExtendedRightsMap,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [Dictionary[guid, PSObject]] $SchemaGuidMap
    )

    $rights         = $Rule.ActiveDirectoryRights
    $rightsDecoded  = $rights.ToString()
    # Mask via Int64 to preserve the unsigned 32-bit bit pattern: an AD ACE
    # can carry an AccessMask whose Int32 representation is negative
    # (e.g. 0xFFFFFFFF -> -1), which the naïve [uint32] cast rejects.
    $accessMask     = [uint32] (([long] [int] $rights) -band 0xFFFFFFFFL)

    $objectTypeGuid = $Rule.ObjectType
    $inheritedGuid  = $Rule.InheritedObjectType

    $hasObjectType = ($objectTypeGuid -ne [guid]::Empty) -or ($inheritedGuid -ne [guid]::Empty)
    $aceTypePrefix = switch ($Rule.AccessControlType) {
        ([AccessControlType]::Allow) { 'AccessAllowed' }
        ([AccessControlType]::Deny)  { 'AccessDenied' }
        default                      { "Access$($Rule.AccessControlType)" }
    }
    $aceType = if ($hasObjectType) { "${aceTypePrefix}Object" } else { $aceTypePrefix }

    $objectTypeName = ''
    $objectTypeKind = 'All'

    if ($objectTypeGuid -ne [guid]::Empty) {
        $resolved = $false

        $isExtendedRight = $rights.HasFlag([ActiveDirectoryRights]::ExtendedRight)
        $isSelf          = $rights.HasFlag([ActiveDirectoryRights]::Self)
        $isReadOrWrite   = $rights.HasFlag([ActiveDirectoryRights]::ReadProperty) -or
                           $rights.HasFlag([ActiveDirectoryRights]::WriteProperty)
        $isCreateOrDelete = $rights.HasFlag([ActiveDirectoryRights]::CreateChild) -or
                            $rights.HasFlag([ActiveDirectoryRights]::DeleteChild)

        if ($isExtendedRight -or $isSelf) {
            $extEntry = $null
            if ($ExtendedRightsMap.TryGetValue($objectTypeGuid, [ref] $extEntry)) {
                $objectTypeName = $extEntry.DisplayName
                $objectTypeKind = $extEntry.RightKind
                $resolved       = $true
            }
        }

        if (-not $resolved -and $isReadOrWrite) {
            $extEntry = $null
            if ($ExtendedRightsMap.TryGetValue($objectTypeGuid, [ref] $extEntry) -and
                $extEntry.RightKind -eq 'PropertySet') {
                $objectTypeName = $extEntry.DisplayName
                $objectTypeKind = 'PropertySet'
                $resolved       = $true
            }
            else {
                $schemaEntry = $null
                if ($SchemaGuidMap.TryGetValue($objectTypeGuid, [ref] $schemaEntry)) {
                    $objectTypeName = $schemaEntry.LdapDisplayName
                    $objectTypeKind = 'Property'
                    $resolved       = $true
                }
            }
        }

        if (-not $resolved -and $isCreateOrDelete) {
            $schemaEntry = $null
            if ($SchemaGuidMap.TryGetValue($objectTypeGuid, [ref] $schemaEntry) -and
                $schemaEntry.ObjectCategory -eq 'classSchema') {
                $objectTypeName = $schemaEntry.LdapDisplayName
                $objectTypeKind = 'ClassChild'
                $resolved       = $true
            }
        }

        if (-not $resolved) {
            $objectTypeKind = 'Unresolved'
        }
    }

    $inheritedName = ''
    if ($inheritedGuid -ne [guid]::Empty) {
        $schemaEntry = $null
        if ($SchemaGuidMap.TryGetValue($inheritedGuid, [ref] $schemaEntry)) {
            $inheritedName = $schemaEntry.LdapDisplayName
        }
    }

    $aceFlags = [AceFlags]::None
    if ($Rule.InheritanceFlags.HasFlag([InheritanceFlags]::ObjectInherit)) {
        $aceFlags = $aceFlags -bor [AceFlags]::ObjectInherit
    }
    if ($Rule.InheritanceFlags.HasFlag([InheritanceFlags]::ContainerInherit)) {
        $aceFlags = $aceFlags -bor [AceFlags]::ContainerInherit
    }
    if ($Rule.PropagationFlags.HasFlag([PropagationFlags]::NoPropagateInherit)) {
        $aceFlags = $aceFlags -bor [AceFlags]::NoPropagateInherit
    }
    if ($Rule.PropagationFlags.HasFlag([PropagationFlags]::InheritOnly)) {
        $aceFlags = $aceFlags -bor [AceFlags]::InheritOnly
    }
    if ($Rule.IsInherited) {
        $aceFlags = $aceFlags -bor [AceFlags]::Inherited
    }

    [PSCustomObject]@{
        ObjectDN                = $ObjectDN
        ObjectClass             = $ObjectClass
        ObjectGUID              = $ObjectGUID
        TrusteeSid              = $Rule.IdentityReference.Value
        AccessMask              = $accessMask
        AccessControlType       = $Rule.AccessControlType.ToString()
        AceType                 = $aceType
        RightsDecoded           = $rightsDecoded
        ObjectTypeGuid          = $objectTypeGuid
        ObjectTypeName          = $objectTypeName
        ObjectTypeKind          = $objectTypeKind
        InheritedObjectTypeGuid = $inheritedGuid
        InheritedObjectTypeName = $inheritedName
        InheritanceFlags        = $Rule.InheritanceFlags.ToString()
        IsInherited             = [bool] $Rule.IsInherited
        IsDaclProtected         = $IsDaclProtected
        AceIndex                = $AceIndex
        AceFlagsRaw             = [byte] [int] $aceFlags
    }
}

function Invoke-AceParsingWorkUnit {
    <#
    .SYNOPSIS
        Parse a batch of objects-with-SD into a flat list of ACE records.

    .DESCRIPTION
        Runspace work-unit body. For each input object: parse the SD; emit
        the synthetic Owner ACE; enumerate DACL access rules and emit one
        record per rule. Per-object parse failures are isolated — a placeholder
        record with RightsDecoded = 'PARSE_ERROR' and AceIndex = -2 is
        emitted in place and the loop continues (plan §14).

        Function-level errors propagate to the runspace and are captured by
        Invoke-RunspacePoolWork as a BatchError.

    .PARAMETER Batch
        List of objects from Phase 2 — each carrying DistinguishedName,
        StructuralObjectClass, ObjectGUID, and NTSecurityDescriptor (byte[]).

    .PARAMETER ExtendedRightsMap
        rightsGuid -> control-access-right map.

    .PARAMETER SchemaGuidMap
        schemaIDGUID -> attribute/class map.
    #>
    [CmdletBinding()]
    [OutputType([List[PSObject]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [List[PSObject]] $Batch,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [Dictionary[guid, PSObject]] $ExtendedRightsMap,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [Dictionary[guid, PSObject]] $SchemaGuidMap
    )

    $records = [List[PSObject]]::new()

    foreach ($obj in $Batch) {
        $parsed = $null
        try {
            $parsed = ConvertFrom-NtSecurityDescriptor -BinaryForm $obj.NTSecurityDescriptor
        }
        catch {
            $records.Add([PSCustomObject]@{
                ObjectDN                = $obj.DistinguishedName
                ObjectClass             = $obj.StructuralObjectClass
                ObjectGUID              = $obj.ObjectGUID
                TrusteeSid              = ''
                AccessMask              = [uint32] 0
                AccessControlType       = ''
                AceType                 = 'PARSE_ERROR'
                RightsDecoded           = 'PARSE_ERROR'
                ObjectTypeGuid          = [guid]::Empty
                ObjectTypeName          = $_.Exception.Message
                ObjectTypeKind          = 'Unresolved'
                InheritedObjectTypeGuid = [guid]::Empty
                InheritedObjectTypeName = ''
                InheritanceFlags        = 'None'
                IsInherited             = $false
                IsDaclProtected         = $false
                AceIndex                = -2
                AceFlagsRaw             = [byte] 0
            })
            continue
        }

        $ownerParams = @{
            OwnerSid        = $parsed.Owner
            ObjectDN        = $obj.DistinguishedName
            ObjectClass     = $obj.StructuralObjectClass
            ObjectGUID      = $obj.ObjectGUID
            IsDaclProtected = $parsed.IsDaclProtected
        }
        $records.Add( (Add-OwnerAce @ownerParams) )

        $rules = $parsed.Dacl.GetAccessRules($true, $true, [SecurityIdentifier])
        for ($i = 0; $i -lt $rules.Count; $i++) {
            $aceParams = @{
                Rule              = $rules[$i]
                AceIndex          = $i
                ObjectDN          = $obj.DistinguishedName
                ObjectClass       = $obj.StructuralObjectClass
                ObjectGUID        = $obj.ObjectGUID
                IsDaclProtected   = $parsed.IsDaclProtected
                ExtendedRightsMap = $ExtendedRightsMap
                SchemaGuidMap     = $SchemaGuidMap
            }
            $records.Add( (ConvertFrom-AdAce @aceParams) )
        }
    }

    , $records
}

function New-RunspacePool {
    <#
    .SYNOPSIS
        Open a runspace pool whose runspaces have the GUID maps and Phase 3
        functions pre-loaded via InitialSessionState.

    .DESCRIPTION
        Per plan §12: each runspace receives the GUID maps as
        SessionStateVariableEntry instances so they aren't rebuilt per batch.
        StartupScripts dot-source the Phase 3 lib file into each runspace,
        which preserves the file's `using namespace` directives —
        SessionStateFunctionEntry would strip them and break short type names
        in function bodies (ADR-006).

        Returns an opened RunspacePool. Caller is responsible for Close +
        Dispose.

    .PARAMETER ThreadCount
        Maximum concurrent runspaces.

    .PARAMETER Variables
        Hashtable of name -> value pairs to inject as session-state variables.
        Each value is referenced (not copied) — mutation in one runspace is
        visible to others, so callers should treat injected dictionaries as
        read-only fixtures (the GUID maps are built once in Phase 1 and never
        mutated, which is the intended use).

    .PARAMETER StartupScripts
        Absolute paths to .ps1 files dot-sourced at the start of each
        runspace. Use this for the Phase 3 lib so functions are in scope when
        the work unit fires.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Returns a freshly-created RunspacePool; the only state mutation is the pool itself.')]
    [CmdletBinding()]
    [OutputType([System.Management.Automation.Runspaces.RunspacePool])]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1, 64)]
        [int] $ThreadCount,

        [Parameter()]
        [hashtable] $Variables,

        [Parameter()]
        [string[]] $StartupScripts
    )

    $iss = [InitialSessionState]::CreateDefault2()

    if ($Variables) {
        foreach ($kvp in $Variables.GetEnumerator()) {
            $entry = [SessionStateVariableEntry]::new($kvp.Key, $kvp.Value, '')
            [void] $iss.Variables.Add($entry)
        }
    }

    if ($StartupScripts) {
        foreach ($path in $StartupScripts) {
            # iss.StartupScripts is a HashSet[string]; .Add returns bool —
            # suppress so it doesn't leak into the function's output pipeline.
            [void] $iss.StartupScripts.Add($path)
        }
    }

    $pool = [runspacefactory]::CreateRunspacePool(1, $ThreadCount, $iss, $Host)
    $pool.Open()

    , $pool
}

function Submit-RunspaceWorkItem {
    <#
    .SYNOPSIS
        Submit a single work item to an opened runspace pool and return a
        handle for later draining.

    .DESCRIPTION
        Creates a [powershell] pipeline bound to -Pool, adds -WorkUnit as
        the script and -Item as its positional argument, then BeginInvokes.
        Returns a PSCustomObject {PowerShell, Handle, Index, Metadata}
        that Receive-RunspaceHandle accepts. The handle does NOT carry the
        input -Item back: each handle would otherwise pin a reference to
        its 250-object batch (with binary nTSecurityDescriptor blobs) that
        no consumer reads, blocking GC until the runspace pool drains.
        See docs/session-changes-2025-05-15.md §5a.

        Extracted from Invoke-RunspacePoolWork (plan §12) so the entry
        script can pipeline Phase 2 batches into the Phase 3 pool as they
        arrive — Phase 3 parsing starts while Phase 2 is still enumerating.

    .PARAMETER Pool
        Opened RunspacePool from New-RunspacePool.

    .PARAMETER WorkUnit
        ScriptBlock invoked once per input. Receives -Item as its only
        positional argument.

    .PARAMETER Item
        The single work-unit input.

    .PARAMETER Index
        Numeric index of this item among its siblings, recorded on the
        handle. Default 0.

    .PARAMETER Metadata
        Optional hashtable passed through to the handle; Receive-RunspaceHandle
        forwards it onto BatchError records so callers can correlate failures
        back to per-item context (NamingContext, BatchSize, etc.).
    #>
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Management.Automation.Runspaces.RunspacePool] $Pool,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [scriptblock] $WorkUnit,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Item,

        [Parameter()]
        [int] $Index = 0,

        [Parameter()]
        [hashtable] $Metadata
    )

    $ps = [powershell]::Create()
    $ps.RunspacePool = $Pool
    [void] $ps.AddScript($WorkUnit).AddArgument($Item)
    [PSCustomObject]@{
        PowerShell = $ps
        Handle     = $ps.BeginInvoke()
        Index      = $Index
        Metadata   = $Metadata
    }
}

function Receive-RunspaceHandle {
    <#
    .SYNOPSIS
        Drain a list of submitted runspace handles, aggregating results and
        capturing per-handle failures to -ErrorBag without throwing.

    .DESCRIPTION
        Iterates -Handles (PSObjects emitted by Submit-RunspaceWorkItem),
        calls EndInvoke on each, and appends pipeline output to the result
        list. Per-handle exceptions become BatchError records on -ErrorBag
        (Event, Index, Error, Metadata) without re-throwing — a single bad
        batch never aborts the run (plan §14). Non-terminating errors left
        on the pipeline's Streams.Error are captured the same way. Always
        disposes the underlying [powershell] pipeline.

    .PARAMETER Handles
        List[PSObject] of handle records from Submit-RunspaceWorkItem.

    .PARAMETER ErrorBag
        Optional sink for BatchError records. The List[PSObject] is the
        script-scoped $ErrorBag in production.
    #>
    [CmdletBinding()]
    [OutputType([List[PSObject]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [List[PSObject]] $Handles,

        [Parameter()]
        [List[PSObject]] $ErrorBag
    )

    $results = [List[PSObject]]::new()
    foreach ($h in $Handles) {
        try {
            $output = $h.PowerShell.EndInvoke($h.Handle)
            foreach ($o in $output) {
                $results.Add($o)
            }
            if ($null -ne $ErrorBag -and $h.PowerShell.Streams.Error.Count -gt 0) {
                foreach ($err in $h.PowerShell.Streams.Error) {
                    $ErrorBag.Add([PSCustomObject]@{
                        Event    = 'BatchError'
                        Index    = $h.Index
                        Error    = $err.Exception.Message
                        Metadata = $h.Metadata
                    })
                }
            }
        }
        catch {
            if ($null -ne $ErrorBag) {
                $ErrorBag.Add([PSCustomObject]@{
                    Event    = 'BatchError'
                    Index    = $h.Index
                    Error    = $_.Exception.Message
                    Metadata = $h.Metadata
                })
            }
        }
        finally {
            $h.PowerShell.Dispose()
        }
    }

    , $results
}

function Write-AceBatchToStream {
    <#
    .SYNOPSIS
        Append one batch of ACE records to an open StreamWriter using the
        Phase 3 CLIXML batch format.

    .DESCRIPTION
        Serialises -Records via [PSSerializer]::Serialize at -Depth 3 (flat
        PSCustomObjects with primitive properties round-trip exactly) and
        appends the resulting CLIXML document to -Writer, preceded by the
        sentinel marker line '<!--===BATCH===-->'. Empty batches are
        skipped (no marker, no document) so the file format stays valid
        even when a runspace returns nothing.

        Format choice (ADR-030): CLIXML per batch beats line-per-object
        JSON for two reasons — (a) round-trips [guid], [byte], [uint32]
        without re-casting on every read; (b) one Serialize/Deserialize
        call per ~50-row batch instead of per row keeps the writer cost
        amortised. Read-AceStream is the matching consumer.

    .PARAMETER Writer
        Open StreamWriter to which the batch is appended.

    .PARAMETER Records
        ACE records as emitted by Invoke-AceParsingWorkUnit (any IEnumerable
        of PSObject). Empty input is a no-op.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Appends to the supplied StreamWriter; the side effect is the documented output.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.IO.StreamWriter] $Writer,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Records
    )

    $count = 0
    $array = [List[PSObject]]::new()
    foreach ($r in $Records) {
        if ($null -eq $r) { continue }
        $array.Add($r)
        $count++
    }
    if ($count -eq 0) { return }

    $xml = [System.Management.Automation.PSSerializer]::Serialize($array.ToArray(), 3)
    $Writer.WriteLine('<!--===BATCH===-->')
    $Writer.WriteLine($xml)
}

function Read-AceStream {
    <#
    .SYNOPSIS
        Stream ACE records back from a Phase 3 CLIXML batch file written by
        Write-AceBatchToStream.

    .DESCRIPTION
        Opens -Path as a forward-only StreamReader, accumulates lines until
        the next '<!--===BATCH===-->' marker (or EOF), deserialises the
        batch via [PSSerializer]::Deserialize, and yields each record to
        the pipeline. The reader holds at most one batch in memory — the
        per-batch buffer is reused via StringBuilder.Clear().

        Deserialised records are Deserialized.System.Management.Automation.PSCustomObject
        instances. Property access by name (.ObjectDN, .AceFlagsRaw, etc.)
        works the same as on the original; primitive types ([guid], [byte],
        [uint32]) are preserved. Downstream consumers that don't need to
        mutate the object can treat them as identical to Phase 3 output.

        Missing input file is a clean no-op (returns nothing) — lets the
        entry script call this unconditionally during Phase 4/5/6 even
        when Phase 3 produced zero records.

    .PARAMETER Path
        Absolute path to the Phase 3 CLIXML batch file.
    #>
    [CmdletBinding()]
    [OutputType([PSObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }

    $reader = [System.IO.StreamReader]::new($Path)
    $buf = [System.Text.StringBuilder]::new()
    try {
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            if ($line -eq '<!--===BATCH===-->') {
                if ($buf.Length -gt 0) {
                    $items = [System.Management.Automation.PSSerializer]::Deserialize($buf.ToString())
                    foreach ($item in $items) { $item }
                    [void] $buf.Clear()
                }
                continue
            }
            [void] $buf.AppendLine($line)
        }
        if ($buf.Length -gt 0) {
            $items = [System.Management.Automation.PSSerializer]::Deserialize($buf.ToString())
            foreach ($item in $items) { $item }
        }
    }
    finally {
        $reader.Dispose()
    }
}

function Invoke-RunspacePoolWork {
    <#
    .SYNOPSIS
        Dispatch a collection of inputs to a runspace pool, aggregate results,
        and capture per-input failures into ErrorBag without throwing.

    .DESCRIPTION
        Thin wrapper that submits every -Input via Submit-RunspaceWorkItem
        and then drains the resulting handles via Receive-RunspaceHandle.
        Use this when the full input set is available up-front; for the
        Phase 2/3 interleaved pipeline pattern, call Submit/Receive
        separately (the entry script does this).

    .PARAMETER Pool
        Opened RunspacePool from New-RunspacePool.

    .PARAMETER WorkUnit
        ScriptBlock invoked once per input. Receives the input as its only
        positional argument.

    .PARAMETER Inputs
        Collection of input items. Each item is dispatched as its own work
        unit.

    .PARAMETER ErrorBag
        Optional sink for BatchError records: Event, Index, Error, Metadata.
        The List[PSObject] is the script-scoped $ErrorBag in production.
    #>
    [CmdletBinding()]
    [OutputType([List[PSObject]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Management.Automation.Runspaces.RunspacePool] $Pool,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [scriptblock] $WorkUnit,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Inputs,

        [Parameter()]
        [List[PSObject]] $ErrorBag
    )

    $handles = [List[PSObject]]::new()
    $index   = 0
    foreach ($item in $Inputs) {
        $submitParams = @{
            Pool     = $Pool
            WorkUnit = $WorkUnit
            Item     = $item
            Index    = $index
        }
        $handles.Add((Submit-RunspaceWorkItem @submitParams))
        $index++
    }

    Receive-RunspaceHandle -Handles $handles -ErrorBag $ErrorBag
}
