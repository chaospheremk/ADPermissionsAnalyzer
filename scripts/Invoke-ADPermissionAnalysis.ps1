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

. (Join-Path -Path $PSScriptRoot -ChildPath 'lib/Phase1-DiscoveryAndMaps.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'lib/Phase2-Enumeration.ps1')

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

    # Phase 3 (Step 4) will hook into the per-batch foreach below to dispatch
    # to the runspace pool. For now we only count and emit progress.
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
            # TODO(Step 4): dispatch $batch to the Phase 3 runspace pool.

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

    # --- Phase 3: ACE parsing (runspace pool) ------------------------------
    # TODO(plan §18.4): ConvertFrom-NtSecurityDescriptor, Add-OwnerAce,
    #                   ConvertFrom-AdAce, Invoke-AceParsingWorkUnit,
    #                   New-RunspacePool, Invoke-RunspacePoolWork.

    # --- Phase 4: Trustee resolution & group expansion ---------------------
    # TODO(plan §18.5): Resolve-TrusteeSid, Expand-GroupTransitive,
    #                   Get-DistinctTrusteeSet, well-known SID skip set.

    # --- Phase 5: Inheritance source resolution ----------------------------
    # TODO(plan §18.6): Resolve-InheritanceSource with composite-key index +
    #                   DACL_PROTECTED short-circuit.

    # --- Phase 6: Output (streaming) ---------------------------------------
    # TODO(plan §18.7-8): Write-DetailCsv (StreamWriter), Write-PivotCsv from
    #                     incrementally-built $PivotStats.

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
    if ($script:LdapConnection) {
        $script:LdapConnection.Dispose()
    }
    if ($script:LogWriter) {
        $script:LogWriter.Flush()
        $script:LogWriter.Dispose()
    }
}

exit $exitCode
