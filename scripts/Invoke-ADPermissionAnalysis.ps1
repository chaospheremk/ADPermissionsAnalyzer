#Requires -Version 7.0
using namespace System.Collections.Generic
using namespace System.IO
using namespace System.Text

<#
.SYNOPSIS
    Produces a comprehensive inventory of every DACL ACE on every object in a single
    Active Directory domain, across all naming contexts, for least-privilege analysis.

.DESCRIPTION
    Skeleton entry point for the AD Permissions Analyzer.

    This step (plan §18.1) wires the parameter surface, the JSONL logging primitive,
    and the top-level execution skeleton. Subsequent steps (§18.2-§18.8) populate the
    six phases: discovery + GUID maps, enumeration, ACE parsing, trustee resolution,
    inheritance source resolution, and CSV output.

    The full implementation specification is in
    docs/AD-Permissions-Analyzer-Plan.md. House style (foreach, .Where({}), typed
    collections, CmdletBinding, structured JSONL logging, no Set-StrictMode, no
    ForEach-Object, no Where-Object) is mandatory throughout.

.PARAMETER Domain
    FQDN of the target domain. Default: the current user's domain (resolved at runtime).

.PARAMETER Server
    Specific domain controller to bind to. Default: DC locator.

.PARAMETER Credential
    Credential to use for the LDAP bind. Default: current process identity.

.PARAMETER OutputDirectory
    Directory where the detail CSV, pivot CSV, and JSONL log are written. Created if
    it does not exist.

.PARAMETER DetailFileName
    Filename for the per-ACE detail CSV. Default: ADPermissions_Detail_<UTC timestamp>.csv

.PARAMETER PivotFileName
    Filename for the per-trustee pivot CSV. Default: ADPermissions_Pivot_<UTC timestamp>.csv

.PARAMETER LogFileName
    Filename for the structured JSONL log. Default: ADPermissions_<UTC timestamp>.jsonl

.PARAMETER BatchSize
    Number of objects per runspace work unit during phase 3 ACE parsing. Default: 250.

.PARAMETER ThreadCount
    Number of runspaces in the pool. Default: [Environment]::ProcessorCount. Values
    above 16 typically waste effort because LDAP becomes the bottleneck.

.PARAMETER PageSize
    LDAP paged-search page size. Default: 1000 (the AD server-side cap).

.PARAMETER IncludeNamingContexts
    Naming contexts to enumerate. Default: Domain, Configuration, Schema, DNS.

.PARAMETER SkipTransitiveExpansion
    Escape hatch: skip transitive group expansion. Group-trustee ACEs are emitted with
    the group as the effective trustee. Default: off.

.EXAMPLE
    .\Invoke-ADPermissionAnalysis.ps1 -OutputDirectory C:\AdPermAudit

    Run against the current domain with default settings.

.EXAMPLE
    $params = @{
        Domain                = '<domain.fqdn>'
        Server                = '<dc-fqdn>'
        OutputDirectory       = 'C:\AdPermAudit'
        ThreadCount           = 8
        IncludeNamingContexts = @('Domain', 'Configuration')
    }
    .\Invoke-ADPermissionAnalysis.ps1 @params

    Run against a specific domain and DC, with limited NCs and a fixed thread count.

.NOTES
    Windows-only. Uses System.DirectoryServices.ActiveDirectorySecurity and
    NTAccount.Translate(); these are not available on .NET on Linux/macOS.

    Permissions: read access to nTSecurityDescriptor on every enumerated object.
    Typically Domain Admins or an explicitly delegated principal.

    Specification: docs/AD-Permissions-Analyzer-Plan.md
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $Domain,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $Server,

    [Parameter()]
    [PSCredential] $Credential,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $OutputDirectory,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $DetailFileName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $PivotFileName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $LogFileName,

    [Parameter()]
    [ValidateRange(1, 10000)]
    [int] $BatchSize = 250,

    [Parameter()]
    [ValidateRange(1, 32)]
    [int] $ThreadCount = [Environment]::ProcessorCount,

    [Parameter()]
    [ValidateRange(100, 1000)]
    [int] $PageSize = 1000,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]] $IncludeNamingContexts = @('Domain', 'Configuration', 'Schema', 'DNS'),

    [Parameter()]
    [switch] $SkipTransitiveExpansion
)

$ErrorActionPreference = 'Stop'

$script:Phase1LibPath = Join-Path -Path $PSScriptRoot -ChildPath 'lib/Phase1-DiscoveryAndMaps.ps1'
$script:Phase2LibPath = Join-Path -Path $PSScriptRoot -ChildPath 'lib/Phase2-Enumeration.ps1'
$script:Phase3LibPath = Join-Path -Path $PSScriptRoot -ChildPath 'lib/Phase3-AceParsing.ps1'
$script:Phase4LibPath = Join-Path -Path $PSScriptRoot -ChildPath 'lib/Phase4-TrusteeResolution.ps1'
$script:Phase5LibPath = Join-Path -Path $PSScriptRoot -ChildPath 'lib/Phase5-InheritanceSource.ps1'
$script:Phase6LibPath = Join-Path -Path $PSScriptRoot -ChildPath 'lib/Phase6-Output.ps1'

. $script:Phase1LibPath
. $script:Phase2LibPath
. $script:Phase3LibPath
. $script:Phase4LibPath
. $script:Phase5LibPath
. $script:Phase6LibPath

# --- Helpers ----------------------------------------------------------------

function Write-LogEvent {
    <#
    .SYNOPSIS
        Append one structured JSONL event to the script-scoped log writer.

    .DESCRIPTION
        Emits a single-line JSON record to $script:LogWriter. Required fields:
        timestamp (ISO-8601 UTC), level, phase, event, message. Optional: data
        (nested hashtable), correlationId. Named Write-LogEvent rather than
        Write-Log because Log is not an approved PowerShell verb.

    .PARAMETER Level
        Severity. INFO, WARN, or ERROR.

    .PARAMETER Phase
        Phase identifier (e.g., Init, Phase1, Phase3, Complete).

    .PARAMETER EventName
        Short event name (e.g., ScriptStart, PhaseStart, OrphanSid). Serialized
        as the JSON field "event".

    .PARAMETER Message
        Human-readable summary.

    .PARAMETER Data
        Optional nested hashtable of structured fields.

    .PARAMETER CorrelationId
        Optional correlation identifier to group related events.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string] $Level,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Phase,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $EventName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Message,

        [Parameter()]
        [hashtable] $Data,

        [Parameter()]
        [string] $CorrelationId
    )

    $entry = [ordered]@{
        timestamp = [DateTime]::UtcNow.ToString('o')
        level     = $Level
        phase     = $Phase
        event     = $EventName
        message   = $Message
    }
    if ($Data)          { $entry['data']          = $Data }
    if ($CorrelationId) { $entry['correlationId'] = $CorrelationId }

    $line = $entry | ConvertTo-Json -Compress -Depth 10
    $script:LogWriter.WriteLine($line)
}

# --- Defaults requiring runtime evaluation ----------------------------------

$timestamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')
if (-not $DetailFileName) { $DetailFileName = "ADPermissions_Detail_$timestamp.csv" }
if (-not $PivotFileName)  { $PivotFileName  = "ADPermissions_Pivot_$timestamp.csv" }
if (-not $LogFileName)    { $LogFileName    = "ADPermissions_$timestamp.jsonl" }

# --- Output paths -----------------------------------------------------------

if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}
$resolvedOutput = (Resolve-Path -LiteralPath $OutputDirectory).Path
$logPath    = Join-Path -Path $resolvedOutput -ChildPath $LogFileName
$detailPath = Join-Path -Path $resolvedOutput -ChildPath $DetailFileName
$pivotPath  = Join-Path -Path $resolvedOutput -ChildPath $PivotFileName

# --- Script-scoped state ----------------------------------------------------

$script:LogWriter = [StreamWriter]::new($logPath, $false, [Encoding]::UTF8)
$script:LogWriter.AutoFlush = $true
$script:ErrorBag  = [List[PSObject]]::new()

$exitCode = 0

try {
    $startData = @{
        domain                  = $Domain
        server                  = $Server
        credentialProvided      = [bool]$Credential
        outputDirectory         = $resolvedOutput
        detailPath              = $detailPath
        pivotPath               = $pivotPath
        logPath                 = $logPath
        batchSize               = $BatchSize
        threadCount             = $ThreadCount
        pageSize                = $PageSize
        includeNamingContexts   = $IncludeNamingContexts
        skipTransitiveExpansion = [bool]$SkipTransitiveExpansion
        powerShellVersion       = $PSVersionTable.PSVersion.ToString()
    }
    $startParams = @{
        Level     = 'INFO'
        Phase     = 'Init'
        EventName = 'ScriptStart'
        Message   = 'AD Permissions Analyzer started.'
        Data      = $startData
    }
    Write-LogEvent @startParams

    # --- Phase 1: Discovery & GUID maps ------------------------------------
    $phase1Start = [DateTime]::UtcNow
    $phase1StartParams = @{
        Level     = 'INFO'
        Phase     = 'Phase1'
        EventName = 'PhaseStart'
        Message   = 'Phase 1: discovery + GUID maps.'
    }
    Write-LogEvent @phase1StartParams

    $connectParams = @{
        Server     = $Server
        Domain     = $Domain
        Credential = $Credential
    }
    $script:LdapConnection = Connect-AdLdap @connectParams

    $namingContexts = Get-ADNamingContext -Connection $script:LdapConnection
    foreach ($nc in $namingContexts) {
        $ncParams = @{
            Level     = 'INFO'
            Phase     = 'Phase1'
            EventName = 'NamingContextDiscovered'
            Message   = "Naming context: $($nc.DistinguishedName) [$($nc.Type)]"
            Data      = @{ distinguishedName = $nc.DistinguishedName; type = $nc.Type }
        }
        Write-LogEvent @ncParams
    }

    $configurationContext = ($namingContexts.Where({ $_.Type -eq 'Configuration' }))[0]
    $schemaContext        = ($namingContexts.Where({ $_.Type -eq 'Schema' }))[0]
    if (-not $configurationContext) { throw 'Configuration NC not present in RootDSE.' }
    if (-not $schemaContext)        { throw 'Schema NC not present in RootDSE.' }

    $extRightsParams = @{
        Connection                 = $script:LdapConnection
        ConfigurationNamingContext = $configurationContext.DistinguishedName
        PageSize                   = $PageSize
    }
    $extendedRightsMap = New-ADExtendedRightsMap @extRightsParams

    $schemaParams = @{
        Connection          = $script:LdapConnection
        SchemaNamingContext = $schemaContext.DistinguishedName
        PageSize            = $PageSize
    }
    $schemaGuidMap = New-ADSchemaGuidMap @schemaParams

    $propertySetMembersMap = New-PropertySetMembersMap @schemaParams
    $wellKnownSidMap       = New-WellKnownSidMap

    if ($extendedRightsMap.Count -eq 0) {
        throw 'ExtendedRightsMap is empty — schema or permissions issue (plan §14).'
    }
    if ($schemaGuidMap.Count -eq 0) {
        throw 'SchemaGuidMap is empty — schema or permissions issue (plan §14).'
    }

    $mapBuiltParams = @{
        Level     = 'INFO'
        Phase     = 'Phase1'
        EventName = 'MapBuilt'
        Message   = 'GUID and SID maps built.'
        Data      = @{
            extendedRights      = $extendedRightsMap.Count
            schemaGuids         = $schemaGuidMap.Count
            propertySets        = $propertySetMembersMap.Count
            wellKnownSids       = $wellKnownSidMap.Count
            namingContextCount  = $namingContexts.Count
        }
    }
    Write-LogEvent @mapBuiltParams

    $phase1ElapsedMs = [int] ([DateTime]::UtcNow - $phase1Start).TotalMilliseconds
    $phase1EndParams = @{
        Level     = 'INFO'
        Phase     = 'Phase1'
        EventName = 'PhaseEnd'
        Message   = 'Phase 1 complete.'
        Data      = @{ elapsedMs = $phase1ElapsedMs }
    }
    Write-LogEvent @phase1EndParams

    # --- Phase 2: Object enumeration ---------------------------------------
    $phase2Start = [DateTime]::UtcNow
    $phase2StartParams = @{
        Level     = 'INFO'
        Phase     = 'Phase2'
        EventName = 'PhaseStart'
        Message   = 'Phase 2: object enumeration.'
    }
    Write-LogEvent @phase2StartParams

    $selectedNcs = $namingContexts.Where({ $_.Type -in $IncludeNamingContexts })
    $progressIntervalObjects = 5000
    $totalObjects = 0

    # --- Phase 3 setup: pool + work unit are ready before enumeration so we
    #     can pipeline batches into the pool as they arrive (plan §12).
    $phase3Start = [DateTime]::UtcNow
    $phase3StartParams = @{
        Level     = 'INFO'
        Phase     = 'Phase3'
        EventName = 'PhaseStart'
        Message   = 'Phase 3: ACE parsing (runspace pool dispatch).'
        Data      = @{ threadCount = $ThreadCount }
    }
    Write-LogEvent @phase3StartParams

    $poolParams = @{
        ThreadCount    = $ThreadCount
        Variables      = @{
            ExtendedRightsMap = $extendedRightsMap
            SchemaGuidMap     = $schemaGuidMap
        }
        StartupScripts = @($script:Phase3LibPath)
    }
    $script:Phase3Pool = New-RunspacePool @poolParams

    $workUnit = {
        param([System.Collections.Generic.List[PSObject]] $Batch)
        $params = @{
            Batch             = $Batch
            ExtendedRightsMap = $ExtendedRightsMap
            SchemaGuidMap     = $SchemaGuidMap
        }
        Invoke-AceParsingWorkUnit @params
    }

    $handles    = [System.Collections.Generic.List[PSObject]]::new()
    $aceRecords = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($nc in $selectedNcs) {
        $ncStart           = [DateTime]::UtcNow
        $ncObjectCount     = 0
        $sinceLastProgress = 0

        $batchParams = @{
            Connection = $script:LdapConnection
            SearchBase = $nc.DistinguishedName
            BatchSize  = $BatchSize
            PageSize   = $PageSize
        }

        foreach ($batch in Get-ADObjectAclBatch @batchParams) {
            $ncObjectCount     += $batch.Count
            $totalObjects      += $batch.Count
            $sinceLastProgress += $batch.Count

            $ps = [powershell]::Create()
            $ps.RunspacePool = $script:Phase3Pool
            [void] $ps.AddScript($workUnit).AddArgument($batch)
            $handles.Add([PSCustomObject]@{
                PowerShell    = $ps
                Handle        = $ps.BeginInvoke()
                NamingContext = $nc.DistinguishedName
                BatchSize     = $batch.Count
            })

            if ($sinceLastProgress -ge $progressIntervalObjects) {
                $progressParams = @{
                    Level     = 'INFO'
                    Phase     = 'Phase2'
                    EventName = 'EnumerationProgress'
                    Message   = "Enumerated $ncObjectCount objects in $($nc.DistinguishedName)."
                    Data      = @{
                        namingContext = $nc.DistinguishedName
                        ncObjectCount = $ncObjectCount
                        totalObjects  = $totalObjects
                    }
                }
                Write-LogEvent @progressParams

                $writeProgressParams = @{
                    Activity         = 'AD Permissions Analyzer - Phase 2'
                    Status           = "$($nc.DistinguishedName): $ncObjectCount objects"
                    CurrentOperation = "Total enumerated: $totalObjects"
                }
                Write-Progress @writeProgressParams

                $sinceLastProgress = 0
            }
        }

        $ncElapsedMs = [int] ([DateTime]::UtcNow - $ncStart).TotalMilliseconds
        $ncCompleteParams = @{
            Level     = 'INFO'
            Phase     = 'Phase2'
            EventName = 'NamingContextComplete'
            Message   = "Naming context $($nc.DistinguishedName) enumerated."
            Data      = @{
                namingContext = $nc.DistinguishedName
                objectCount   = $ncObjectCount
                elapsedMs     = $ncElapsedMs
            }
        }
        Write-LogEvent @ncCompleteParams

        if ($ncObjectCount -eq 0) {
            $emptyParams = @{
                Level     = 'WARN'
                Phase     = 'Phase2'
                EventName = 'EmptyNamingContext'
                Message   = "Naming context $($nc.DistinguishedName) returned no objects."
                Data      = @{ namingContext = $nc.DistinguishedName }
            }
            Write-LogEvent @emptyParams
        }
    }

    Write-Progress -Activity 'AD Permissions Analyzer - Phase 2' -Completed

    $phase2ElapsedMs = [int] ([DateTime]::UtcNow - $phase2Start).TotalMilliseconds
    $phase2EndParams = @{
        Level     = 'INFO'
        Phase     = 'Phase2'
        EventName = 'PhaseEnd'
        Message   = 'Phase 2 complete.'
        Data      = @{
            totalObjects             = $totalObjects
            namingContextsEnumerated = $selectedNcs.Count
            elapsedMs                = $phase2ElapsedMs
        }
    }
    Write-LogEvent @phase2EndParams

    # --- Phase 3 drain: collect parsed ACE records from queued runspaces ---
    foreach ($h in $handles) {
        try {
            $batchResult = $h.PowerShell.EndInvoke($h.Handle)
            foreach ($r in $batchResult) {
                $aceRecords.Add($r)
            }
        }
        catch {
            $errorRecord = [PSCustomObject]@{
                Event         = 'BatchError'
                Phase         = 'Phase3'
                NamingContext = $h.NamingContext
                BatchSize     = $h.BatchSize
                Error         = $_.Exception.Message
            }
            $script:ErrorBag.Add($errorRecord)

            $batchErrParams = @{
                Level     = 'WARN'
                Phase     = 'Phase3'
                EventName = 'BatchError'
                Message   = "Phase 3 batch failed: $($_.Exception.Message)"
                Data      = @{
                    namingContext = $h.NamingContext
                    batchSize     = $h.BatchSize
                }
            }
            Write-LogEvent @batchErrParams
        }
        finally {
            $h.PowerShell.Dispose()
        }
    }

    $phase3ElapsedMs = [int] ([DateTime]::UtcNow - $phase3Start).TotalMilliseconds
    $phase3EndParams = @{
        Level     = 'INFO'
        Phase     = 'Phase3'
        EventName = 'PhaseEnd'
        Message   = 'Phase 3 complete.'
        Data      = @{
            totalObjects = $totalObjects
            totalAces    = $aceRecords.Count
            batchCount   = $handles.Count
            elapsedMs    = $phase3ElapsedMs
        }
    }
    Write-LogEvent @phase3EndParams

    # --- Phase 4: Trustee resolution & group expansion ---------------------
    $phase4Start = [DateTime]::UtcNow
    $phase4StartParams = @{
        Level     = 'INFO'
        Phase     = 'Phase4'
        EventName = 'PhaseStart'
        Message   = 'Phase 4: trustee resolution + group expansion.'
    }
    Write-LogEvent @phase4StartParams

    $domainContext = ($namingContexts.Where({ $_.Type -eq 'Domain' }))[0]
    if (-not $domainContext) {
        throw 'Domain NC not present in RootDSE — Phase 4 cannot resolve trustees.'
    }

    $domainSid = Get-DomainSid -Connection $script:LdapConnection `
                               -DomainNamingContext $domainContext.DistinguishedName
    $skipSet   = New-WellKnownSidSkipSet -DomainSid $domainSid

    $script:TrusteeCache = [Dictionary[string, PSObject]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $script:GroupExpansionCache = [Dictionary[string, List[PSObject]]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    $distinctTrustees = Get-DistinctTrusteeSet -AceRecords $aceRecords
    $orphanCount      = 0
    $loggedOrphans    = [HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    foreach ($sid in $distinctTrustees) {
        $resolveParams = @{
            Sid                 = $sid
            Cache               = $script:TrusteeCache
            WellKnownSidMap     = $wellKnownSidMap
            Connection          = $script:LdapConnection
            DomainNamingContext = $domainContext.DistinguishedName
        }
        $trustee = Resolve-TrusteeSid @resolveParams

        if ($trustee.PrincipalType -eq 'Orphaned') {
            $orphanCount++
            if ($loggedOrphans.Add($sid)) {
                $orphanParams = @{
                    Level     = 'INFO'
                    Phase     = 'Phase4'
                    EventName = 'OrphanSid'
                    Message   = "Orphan trustee SID: $sid"
                    Data      = @{ sid = $sid }
                }
                Write-LogEvent @orphanParams
            }
        }
    }

    $expansionLookups = 0
    $expansionHits    = 0
    $expansionMisses  = 0
    if (-not $SkipTransitiveExpansion) {
        foreach ($kvp in $script:TrusteeCache.GetEnumerator()) {
            $trustee = $kvp.Value
            if ($trustee.PrincipalType -ne 'Group') { continue }
            if (-not $trustee.DistinguishedName)   { continue }
            if (Test-IsTerminalSid -Sid $trustee.Sid -SkipSet $skipSet) { continue }

            $expansionLookups++
            if ($script:GroupExpansionCache.ContainsKey($trustee.Sid)) {
                $expansionHits++
                continue
            }
            $expansionMisses++

            $expandParams = @{
                GroupSid               = $trustee.Sid
                GroupDistinguishedName = $trustee.DistinguishedName
                Cache                  = $script:GroupExpansionCache
                Connection             = $script:LdapConnection
                DomainNamingContext    = $domainContext.DistinguishedName
            }
            [void] (Expand-GroupTransitive @expandParams)
        }
    }

    $hitRatio = if ($expansionLookups -gt 0) {
        [math]::Round($expansionHits / $expansionLookups, 4)
    }
    else { 0.0 }

    $phase4ElapsedMs = [int] ([DateTime]::UtcNow - $phase4Start).TotalMilliseconds
    $phase4EndParams = @{
        Level     = 'INFO'
        Phase     = 'Phase4'
        EventName = 'PhaseEnd'
        Message   = 'Phase 4 complete.'
        Data      = @{
            distinctTrustees       = $distinctTrustees.Count
            resolvedTrustees       = $script:TrusteeCache.Count
            orphanCount            = $orphanCount
            expandedGroups         = $expansionMisses
            expansionLookups       = $expansionLookups
            expansionCacheHitRatio = $hitRatio
            domainSid              = $domainSid
            skipTransitiveExpansion = [bool] $SkipTransitiveExpansion
            elapsedMs              = $phase4ElapsedMs
        }
    }
    Write-LogEvent @phase4EndParams

    # --- Phase 5: Inheritance source resolution ----------------------------
    $phase5Start = [DateTime]::UtcNow
    $phase5StartParams = @{
        Level     = 'INFO'
        Phase     = 'Phase5'
        EventName = 'PhaseStart'
        Message   = 'Phase 5: inheritance source resolution.'
    }
    Write-LogEvent @phase5StartParams

    $aceIndex = New-AceIndex -AceRecords $aceRecords

    $ncDns = [List[string]]::new()
    foreach ($nc in $namingContexts) {
        $ncDns.Add($nc.DistinguishedName)
    }

    $protectedDaclAnomalies = [List[PSObject]]::new()
    $resolveParams = @{
        AceRecords                      = $aceRecords
        AceIndex                        = $aceIndex
        NamingContextDistinguishedNames = $ncDns.ToArray()
        ProtectedDaclAnomalies          = $protectedDaclAnomalies
    }
    $phase5Stats = Resolve-InheritanceSource @resolveParams

    foreach ($anomaly in $protectedDaclAnomalies) {
        $anomalyParams = @{
            Level     = 'WARN'
            Phase     = 'Phase5'
            EventName = 'BatchError'
            Message   = "InheritedAceOnProtectedDacl on $($anomaly.ObjectDN)."
            Data      = @{
                reason     = 'InheritedAceOnProtectedDacl'
                objectDN   = $anomaly.ObjectDN
                trusteeSid = $anomaly.TrusteeSid
                accessMask = $anomaly.AccessMask
                aceIndex   = $anomaly.AceIndex
            }
        }
        Write-LogEvent @anomalyParams
        $script:ErrorBag.Add($anomaly)
    }

    $phase5ElapsedMs = [int] ([DateTime]::UtcNow - $phase5Start).TotalMilliseconds
    $phase5EndParams = @{
        Level     = 'INFO'
        Phase     = 'Phase5'
        EventName = 'PhaseEnd'
        Message   = 'Phase 5 complete.'
        Data      = @{
            indexed         = $phase5Stats.Indexed
            inheritedTotal  = $phase5Stats.InheritedTotal
            resolved        = $phase5Stats.Resolved
            unresolved      = $phase5Stats.Unresolved
            protectedDacl   = $phase5Stats.ProtectedDacl
            elapsedMs       = $phase5ElapsedMs
        }
    }
    Write-LogEvent @phase5EndParams

    # --- Phase 6: Output (streaming) ---------------------------------------
    $phase6Start = [DateTime]::UtcNow
    $phase6StartParams = @{
        Level     = 'INFO'
        Phase     = 'Phase6'
        EventName = 'PhaseStart'
        Message   = 'Phase 6: detail CSV streaming + pivot accumulator.'
        Data      = @{ detailPath = $detailPath }
    }
    Write-LogEvent @phase6StartParams

    $script:PivotStats = [Dictionary[string, PSObject]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $collectedAt = [DateTime]::UtcNow.ToString('o')

    $progressCallback = {
        param([hashtable] $Data)
        $progressParams = @{
            Level     = 'INFO'
            Phase     = 'Phase6'
            EventName = 'Phase6Progress'
            Message   = "Phase 6 wrote $($Data.rowsWritten) detail rows."
            Data      = $Data
        }
        Write-LogEvent @progressParams

        $writeProgressParams = @{
            Activity         = 'AD Permissions Analyzer - Phase 6'
            Status           = "$($Data.rowsWritten) rows written"
            CurrentOperation = "Elapsed: $($Data.elapsedMs) ms"
        }
        Write-Progress @writeProgressParams
    }

    $detailParams = @{
        DetailPath          = $detailPath
        AceRecords          = $aceRecords
        TrusteeCache        = $script:TrusteeCache
        GroupExpansionCache = $script:GroupExpansionCache
        NamingContexts      = $namingContexts.ToArray()
        PivotStats          = $script:PivotStats
        CollectedAt         = $collectedAt
        ProgressInterval    = 50000
        ProgressCallback    = $progressCallback
    }
    $detailRowCount = Write-DetailCsv @detailParams

    Write-Progress -Activity 'AD Permissions Analyzer - Phase 6' -Completed

    $phase6ElapsedMs = [int] ([DateTime]::UtcNow - $phase6Start).TotalMilliseconds
    $phase6EndParams = @{
        Level     = 'INFO'
        Phase     = 'Phase6'
        EventName = 'PhaseEnd'
        Message   = 'Phase 6 detail CSV complete.'
        Data      = @{
            detailRowCount    = $detailRowCount
            distinctTrustees  = $script:PivotStats.Count
            elapsedMs         = $phase6ElapsedMs
        }
    }
    Write-LogEvent @phase6EndParams

    # --- Phase 6 (cont.): Pivot CSV (incremental → flush) -----------------
    $pivotStart = [DateTime]::UtcNow
    $pivotStartParams = @{
        Level     = 'INFO'
        Phase     = 'Phase6'
        EventName = 'PivotStart'
        Message   = 'Phase 6: pivot CSV write.'
        Data      = @{ pivotPath = $pivotPath }
    }
    Write-LogEvent @pivotStartParams

    $pivotParams = @{
        PivotPath   = $pivotPath
        Stats       = $script:PivotStats
        CollectedAt = $collectedAt
    }
    $pivotRowCount = Write-PivotCsv @pivotParams

    $pivotElapsedMs = [int] ([DateTime]::UtcNow - $pivotStart).TotalMilliseconds
    $pivotEndParams = @{
        Level     = 'INFO'
        Phase     = 'Phase6'
        EventName = 'PivotEnd'
        Message   = 'Phase 6 pivot CSV complete.'
        Data      = @{
            pivotRowCount = $pivotRowCount
            elapsedMs     = $pivotElapsedMs
        }
    }
    Write-LogEvent @pivotEndParams

    $endData = @{
        errorCount = $script:ErrorBag.Count
        detailPath = $detailPath
        pivotPath  = $pivotPath
        logPath    = $logPath
    }
    $endParams = @{
        Level     = 'INFO'
        Phase     = 'Complete'
        EventName = 'ScriptEnd'
        Message   = 'AD Permissions Analyzer completed.'
        Data      = $endData
    }
    Write-LogEvent @endParams

    if ($script:ErrorBag.Count -gt 0) { $exitCode = 2 }
}
catch {
    $exitCode = 1
    $fatalParams = @{
        Level     = 'ERROR'
        Phase     = 'Fatal'
        EventName = 'ScriptFatal'
        Message   = $_.Exception.Message
        Data      = @{
            exceptionType    = $_.Exception.GetType().FullName
            scriptStackTrace = $_.ScriptStackTrace
        }
    }
    try { Write-LogEvent @fatalParams } catch {
        # Logging failed inside the fatal handler — the original error is still
        # surfaced via Write-Error below, so swallow this one.
        $null = $_
    }
    Write-Error -ErrorRecord $_ -ErrorAction Continue
}
finally {
    if ($script:Phase3Pool) {
        try { $script:Phase3Pool.Close() } catch { $null = $_ }
        $script:Phase3Pool.Dispose()
    }
    if ($script:LdapConnection) {
        $script:LdapConnection.Dispose()
    }
    if ($script:LogWriter) {
        $script:LogWriter.Flush()
        $script:LogWriter.Dispose()
    }
}

exit $exitCode
