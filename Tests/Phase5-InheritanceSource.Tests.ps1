#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

using namespace System.Collections.Generic
using namespace System.Security.AccessControl

BeforeAll {
    $script:LibDir = Join-Path $PSScriptRoot '../scripts/lib'
    # Phase 3 lib hosts the streaming primitives the Phase 5 streaming
    # variant consumes (Write-AceBatchToStream / Read-AceStream).
    . (Join-Path $script:LibDir 'Phase3-AceParsing.ps1')
    . (Join-Path $script:LibDir 'Phase5-InheritanceSource.ps1')

    # ACE flag constants for fixtures — wraps [byte] [AceFlags] casts in
    # readable names so test bodies don't have to decode bit math.
    $script:AfContainer    = [byte] [AceFlags]::ContainerInherit
    $script:AfObject       = [byte] [AceFlags]::ObjectInherit
    $script:AfBoth         = [byte] ([AceFlags]::ContainerInherit -bor [AceFlags]::ObjectInherit)
    $script:AfNoPropagate  = [byte] ([AceFlags]::ContainerInherit -bor [AceFlags]::ObjectInherit -bor [AceFlags]::NoPropagateInherit)
    $script:AfInheritOnly  = [byte] ([AceFlags]::ContainerInherit -bor [AceFlags]::ObjectInherit -bor [AceFlags]::InheritOnly)

    function New-AceRow {
        param(
            [Parameter(Mandatory)] [string] $ObjectDN,
            [Parameter(Mandatory)] [string] $ObjectClass,
            [Parameter(Mandatory)] [AllowEmptyString()] [string] $TrusteeSid,
            [Parameter(Mandatory)] [uint32] $AccessMask,
            [Parameter()]          [guid]   $ObjectTypeGuid = [guid]::Empty,
            [Parameter()]          [string] $InheritedObjectTypeName = '',
            [Parameter()]          [bool]   $IsInherited = $false,
            [Parameter()]          [bool]   $IsDaclProtected = $false,
            [Parameter()]          [int]    $AceIndex = 0,
            [Parameter()]          [byte]   $AceFlagsRaw = 0
        )
        # The streaming Phase 5 rewriter copies every property of the input
        # record onto the output (Resolve-InheritanceSourceStream's row
        # builder), so the fixture must carry the full Phase 3 schema even
        # though the propagation rules only key on a small subset.
        [PSCustomObject]@{
            ObjectDN                = $ObjectDN
            ObjectClass             = $ObjectClass
            ObjectGUID              = [guid]::Empty
            TrusteeSid              = $TrusteeSid
            AccessMask              = $AccessMask
            AccessControlType       = 'Allow'
            AceType                 = 'AccessAllowed'
            RightsDecoded           = 'ReadProperty, WriteProperty'
            ObjectTypeGuid          = $ObjectTypeGuid
            ObjectTypeName          = ''
            ObjectTypeKind          = 'All'
            InheritedObjectTypeGuid = [guid]::Empty
            InheritedObjectTypeName = $InheritedObjectTypeName
            InheritanceFlags        = 'None'
            IsInherited             = $IsInherited
            IsDaclProtected         = $IsDaclProtected
            AceIndex                = $AceIndex
            AceFlagsRaw             = $AceFlagsRaw
        }
    }

    function Write-Phase3Fixture {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)] [string] $Path,
            [Parameter(Mandatory)] [List[PSObject]] $Records
        )
        $writer = [System.IO.StreamWriter]::new($Path, $false, [System.Text.UTF8Encoding]::new($false))
        try {
            Write-AceBatchToStream -Writer $writer -Records $Records
            $writer.Flush()
        }
        finally {
            $writer.Dispose()
        }
    }

    function Read-Phase5Records {
        [CmdletBinding()]
        [OutputType([List[PSObject]])]
        param([Parameter(Mandatory)] [string] $Path)
        $list = [List[PSObject]]::new()
        foreach ($r in (Read-AceStream -Path $Path)) {
            $list.Add($r)
        }
        , $list
    }

    function Invoke-Phase5Stream {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)] [List[PSObject]] $Records,
            [Parameter(Mandatory)] [string[]] $NamingContextDistinguishedNames,
            [Parameter()]          [List[PSObject]] $ProtectedDaclAnomalies
        )
        $workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("phase5-stream-{0}" -f ([guid]::NewGuid()))
        New-Item -ItemType Directory -Path $workDir -Force | Out-Null
        try {
            $inputPath  = Join-Path $workDir 'phase3.clixml'
            $outputPath = Join-Path $workDir 'phase5.clixml'
            Write-Phase3Fixture -Path $inputPath -Records $Records

            $index = New-AceIndexFromStream -Phase3AceRecordsPath $inputPath
            $resolveParams = @{
                Phase3AceRecordsPath            = $inputPath
                Phase5OutputPath                = $outputPath
                AceIndex                        = $index
                NamingContextDistinguishedNames = $NamingContextDistinguishedNames
            }
            if ($PSBoundParameters.ContainsKey('ProtectedDaclAnomalies')) {
                $resolveParams['ProtectedDaclAnomalies'] = $ProtectedDaclAnomalies
            }
            $stats   = Resolve-InheritanceSourceStream @resolveParams
            $written = Read-Phase5Records -Path $outputPath
            [PSCustomObject]@{
                Index   = $index
                Stats   = $stats
                Records = $written
            }
        }
        finally {
            Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $script:DomainNc   = 'DC=lab,DC=local'
    $script:TrusteeSid = 'S-1-5-21-100-200-300-1001'
    $script:Mask       = [uint32] 0x20020   # ReadProperty | WriteProperty (sample)
}

Describe 'New-AceIndexFromStream' {
    BeforeAll {
        $script:IndexWorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ("phase5-index-{0}" -f ([guid]::NewGuid()))
        New-Item -ItemType Directory -Path $script:IndexWorkDir -Force | Out-Null

        function Invoke-NewAceIndex {
            param([Parameter(Mandatory)] [List[PSObject]] $Records)
            $path = Join-Path $script:IndexWorkDir ("index-{0}.clixml" -f ([guid]::NewGuid()))
            Write-Phase3Fixture -Path $path -Records $Records
            New-AceIndexFromStream -Phase3AceRecordsPath $path
        }
    }

    AfterAll {
        if (Test-Path -LiteralPath $script:IndexWorkDir) {
            Remove-Item -LiteralPath $script:IndexWorkDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'indexes explicit rows by composite key' {
        $records = [List[PSObject]]::new()
        $records.Add( (New-AceRow `
            -ObjectDN "OU=Users,$script:DomainNc" `
            -ObjectClass 'organizationalUnit' `
            -TrusteeSid $script:TrusteeSid `
            -AccessMask $script:Mask `
            -AceFlagsRaw $script:AfBoth) )

        $index = Invoke-NewAceIndex -Records $records
        $index.Count | Should -Be 1

        $key = [ValueTuple[string, string, uint32, guid]]::new(
            "OU=USERS,$($script:DomainNc.ToUpperInvariant())",
            $script:TrusteeSid, $script:Mask, [guid]::Empty)
        $index.ContainsKey($key) | Should -BeTrue
        $index[$key].Count        | Should -Be 1
    }

    It 'bucket values carry the compact payload (AceFlagsRaw + InheritedObjectTypeName only)' {
        $records = [List[PSObject]]::new()
        $records.Add( (New-AceRow `
            -ObjectDN "OU=Users,$script:DomainNc" `
            -ObjectClass 'organizationalUnit' `
            -TrusteeSid $script:TrusteeSid `
            -AccessMask $script:Mask `
            -InheritedObjectTypeName 'user' `
            -AceFlagsRaw $script:AfBoth) )

        $index  = Invoke-NewAceIndex -Records $records
        $bucket = $index.Values | Select-Object -First 1
        $bucket[0].AceFlagsRaw             | Should -Be $script:AfBoth
        $bucket[0].InheritedObjectTypeName | Should -Be 'user'
        # Compact payload — the bucket entry does NOT carry the full Phase 3 row.
        $bucket[0].PSObject.Properties.Name.Count | Should -Be 2
    }

    It 'skips inherited rows (IsInherited = true)' {
        $records = [List[PSObject]]::new()
        $records.Add( (New-AceRow `
            -ObjectDN "CN=u1,OU=Users,$script:DomainNc" `
            -ObjectClass 'user' `
            -TrusteeSid $script:TrusteeSid `
            -AccessMask $script:Mask `
            -IsInherited $true) )

        $index = Invoke-NewAceIndex -Records $records
        $index.Count | Should -Be 0
    }

    It 'skips Synthetic.Owner (AceIndex = -1) and PARSE_ERROR (AceIndex = -2) rows' {
        $records = [List[PSObject]]::new()
        $records.Add( (New-AceRow `
            -ObjectDN "OU=Users,$script:DomainNc" `
            -ObjectClass 'organizationalUnit' `
            -TrusteeSid $script:TrusteeSid `
            -AccessMask $script:Mask `
            -AceIndex -1) )
        $records.Add( (New-AceRow `
            -ObjectDN "OU=Bad,$script:DomainNc" `
            -ObjectClass 'organizationalUnit' `
            -TrusteeSid '' `
            -AccessMask 0 `
            -AceIndex -2) )

        $index = Invoke-NewAceIndex -Records $records
        $index.Count | Should -Be 0
    }

    It 'stacks composite-key collisions into the same bucket' {
        $records = [List[PSObject]]::new()
        $records.Add( (New-AceRow `
            -ObjectDN "OU=Users,$script:DomainNc" `
            -ObjectClass 'organizationalUnit' `
            -TrusteeSid $script:TrusteeSid `
            -AccessMask $script:Mask `
            -AceIndex 0 `
            -AceFlagsRaw $script:AfContainer) )
        $records.Add( (New-AceRow `
            -ObjectDN "OU=Users,$script:DomainNc" `
            -ObjectClass 'organizationalUnit' `
            -TrusteeSid $script:TrusteeSid `
            -AccessMask $script:Mask `
            -AceIndex 1 `
            -AceFlagsRaw $script:AfObject) )

        $index = Invoke-NewAceIndex -Records $records
        $index.Count | Should -Be 1

        $bucket = $index.Values | Select-Object -First 1
        $bucket.Count | Should -Be 2
    }
}

Describe 'Get-ParentDistinguishedName' {
    It 'strips the leftmost RDN of a standard DN' {
        Get-ParentDistinguishedName -DistinguishedName "CN=Bob,OU=Users,$script:DomainNc" |
            Should -Be "OU=Users,$script:DomainNc"
    }

    It 'preserves an escaped comma inside the RDN value' {
        # 'CN=Smith\, John,DC=lab,DC=local' — escape \, is part of the CN
        # value, the second comma is the RDN separator.
        $dn = 'CN=Smith\, John,DC=lab,DC=local'
        Get-ParentDistinguishedName -DistinguishedName $dn |
            Should -Be 'DC=lab,DC=local'
    }

    It 'returns $null for an NC root (single component)' {
        Get-ParentDistinguishedName -DistinguishedName 'DC=local' |
            Should -BeNullOrEmpty
    }

    It 'returns $null for empty input' {
        Get-ParentDistinguishedName -DistinguishedName '' |
            Should -BeNullOrEmpty
    }
}

Describe 'Test-InheritanceFlagsPropagateTo' {
    It 'ContainerInherit propagates to a container descendant (organizationalUnit)' {
        $params = @{
            AceFlagsRaw             = $script:AfContainer
            InheritedObjectTypeName = ''
            DescendantClass         = 'organizationalUnit'
            IsDirectChild           = $true
        }
        Test-InheritanceFlagsPropagateTo @params | Should -BeTrue
    }

    It 'ContainerInherit alone does NOT propagate to a leaf descendant (user)' {
        $params = @{
            AceFlagsRaw             = $script:AfContainer
            InheritedObjectTypeName = ''
            DescendantClass         = 'user'
            IsDirectChild           = $true
        }
        Test-InheritanceFlagsPropagateTo @params | Should -BeFalse
    }

    It 'ObjectInherit propagates to a leaf descendant (user)' {
        $params = @{
            AceFlagsRaw             = $script:AfObject
            InheritedObjectTypeName = ''
            DescendantClass         = 'user'
            IsDirectChild           = $true
        }
        Test-InheritanceFlagsPropagateTo @params | Should -BeTrue
    }

    It 'ObjectInherit alone does NOT propagate to a container descendant' {
        $params = @{
            AceFlagsRaw             = $script:AfObject
            InheritedObjectTypeName = ''
            DescendantClass         = 'organizationalUnit'
            IsDirectChild           = $true
        }
        Test-InheritanceFlagsPropagateTo @params | Should -BeFalse
    }

    It 'InheritOnly does not block descendant propagation (it only suppresses self)' {
        $params = @{
            AceFlagsRaw             = $script:AfInheritOnly
            InheritedObjectTypeName = ''
            DescendantClass         = 'user'
            IsDirectChild           = $true
        }
        Test-InheritanceFlagsPropagateTo @params | Should -BeTrue
    }

    It 'NoPropagateInherit propagates to direct child (level 1)' {
        $params = @{
            AceFlagsRaw             = $script:AfNoPropagate
            InheritedObjectTypeName = ''
            DescendantClass         = 'user'
            IsDirectChild           = $true
        }
        Test-InheritanceFlagsPropagateTo @params | Should -BeTrue
    }

    It 'NoPropagateInherit halts beyond the first level (level 2+)' {
        $params = @{
            AceFlagsRaw             = $script:AfNoPropagate
            InheritedObjectTypeName = ''
            DescendantClass         = 'user'
            IsDirectChild           = $false
        }
        Test-InheritanceFlagsPropagateTo @params | Should -BeFalse
    }

    It 'InheritedObjectType filter "user" matches a user descendant' {
        $params = @{
            AceFlagsRaw             = $script:AfBoth
            InheritedObjectTypeName = 'user'
            DescendantClass         = 'user'
            IsDirectChild           = $true
        }
        Test-InheritanceFlagsPropagateTo @params | Should -BeTrue
    }

    It 'InheritedObjectType filter "user" excludes a group descendant' {
        $params = @{
            AceFlagsRaw             = $script:AfBoth
            InheritedObjectTypeName = 'user'
            DescendantClass         = 'group'
            IsDirectChild           = $true
        }
        Test-InheritanceFlagsPropagateTo @params | Should -BeFalse
    }

    It 'returns false when neither ContainerInherit nor ObjectInherit is set' {
        $params = @{
            AceFlagsRaw             = [byte] 0
            InheritedObjectTypeName = ''
            DescendantClass         = 'user'
            IsDirectChild           = $true
        }
        Test-InheritanceFlagsPropagateTo @params | Should -BeFalse
    }
}

Describe 'Resolve-InheritanceSourceStream' {
    BeforeEach {
        $script:NcRoots = @($script:DomainNc)
    }

    It 'resolves an inherited child ACE to the direct parent OU explicit ACE' {
        $records = [List[PSObject]]::new()
        $records.Add( (New-AceRow `
            -ObjectDN "OU=Users,$script:DomainNc" `
            -ObjectClass 'organizationalUnit' `
            -TrusteeSid $script:TrusteeSid `
            -AccessMask $script:Mask `
            -AceIndex 0 `
            -AceFlagsRaw $script:AfBoth) )
        $records.Add( (New-AceRow `
            -ObjectDN "CN=u1,OU=Users,$script:DomainNc" `
            -ObjectClass 'user' `
            -TrusteeSid $script:TrusteeSid `
            -AccessMask $script:Mask `
            -IsInherited $true `
            -AceIndex 0) )

        $result = Invoke-Phase5Stream `
            -Records $records `
            -NamingContextDistinguishedNames $script:NcRoots

        $result.Stats.InheritedTotal | Should -Be 1
        $result.Stats.Resolved       | Should -Be 1
        $result.Stats.Unresolved     | Should -Be 0
        $result.Stats.ProtectedDacl  | Should -Be 0

        $result.Records[1].InheritanceSourceDN   | Should -Be "OU=Users,$script:DomainNc"
        $result.Records[1].InheritanceSourceNote | Should -BeNullOrEmpty
    }

    It 'walks past a level-1 ancestor whose candidate fails propagation, finds the level-2 match' {
        # Level-1 parent (OU=Users) has the SAME composite key but the ACE
        # is ObjectInherit-only — fails propagation to a CONTAINER descendant
        # below. Level-2 parent (DC=lab,DC=local) has an explicit ACE with
        # ContainerInherit, which should win.
        $records = [List[PSObject]]::new()

        # The descendant we're resolving — a sub-OU under OU=Users.
        $records.Add( (New-AceRow `
            -ObjectDN "OU=Sub,OU=Users,$script:DomainNc" `
            -ObjectClass 'organizationalUnit' `
            -TrusteeSid $script:TrusteeSid `
            -AccessMask $script:Mask `
            -IsInherited $true `
            -AceIndex 0) )

        # Level-1 candidate — ObjectInherit only (excludes the OU descendant).
        $records.Add( (New-AceRow `
            -ObjectDN "OU=Users,$script:DomainNc" `
            -ObjectClass 'organizationalUnit' `
            -TrusteeSid $script:TrusteeSid `
            -AccessMask $script:Mask `
            -AceIndex 0 `
            -AceFlagsRaw $script:AfObject) )

        # Level-2 candidate — at the NC root, ContainerInherit set.
        $records.Add( (New-AceRow `
            -ObjectDN $script:DomainNc `
            -ObjectClass 'domainDNS' `
            -TrusteeSid $script:TrusteeSid `
            -AccessMask $script:Mask `
            -AceIndex 0 `
            -AceFlagsRaw $script:AfContainer) )

        $result = Invoke-Phase5Stream `
            -Records $records `
            -NamingContextDistinguishedNames $script:NcRoots

        $result.Stats.Resolved              | Should -Be 1
        $result.Records[0].InheritanceSourceDN | Should -Be $script:DomainNc
    }

    It 'stops the parent walk at the Configuration NC root and does not cross into the Domain NC' {
        # An inherited row inside the Configuration NC must resolve from
        # within Configuration only — never from an explicit ACE on the
        # Domain NC root. The Domain-root ACE here is a trap: if the walk
        # crosses the NC boundary it would resolve incorrectly to that row.
        $configNc = "CN=Configuration,$script:DomainNc"
        $nc       = @($configNc, $script:DomainNc)

        $records = [List[PSObject]]::new()

        # Inherited descendant inside the Configuration NC.
        $records.Add( (New-AceRow `
            -ObjectDN "CN=Sites,$configNc" `
            -ObjectClass 'sitesContainer' `
            -TrusteeSid $script:TrusteeSid `
            -AccessMask $script:Mask `
            -IsInherited $true `
            -AceIndex 0) )

        # Trap: an explicit ACE on the Domain NC root with a matching
        # composite key (same trustee + access mask + ContainerInherit).
        # If the walk crossed into Domain NC, this would be picked up.
        $records.Add( (New-AceRow `
            -ObjectDN $script:DomainNc `
            -ObjectClass 'domainDNS' `
            -TrusteeSid $script:TrusteeSid `
            -AccessMask $script:Mask `
            -AceIndex 0 `
            -AceFlagsRaw $script:AfContainer) )

        $result = Invoke-Phase5Stream `
            -Records $records `
            -NamingContextDistinguishedNames $nc

        $result.Stats.InheritedTotal | Should -Be 1
        $result.Stats.Resolved       | Should -Be 0
        $result.Stats.Unresolved     | Should -Be 1
        $result.Records[0].InheritanceSourceDN   | Should -BeNullOrEmpty
        $result.Records[0].InheritanceSourceNote | Should -Not -BeNullOrEmpty
    }

    It 'short-circuits a DACL_PROTECTED inherited row and emits an anomaly' {
        $records = [List[PSObject]]::new()
        $records.Add( (New-AceRow `
            -ObjectDN "OU=Users,$script:DomainNc" `
            -ObjectClass 'organizationalUnit' `
            -TrusteeSid $script:TrusteeSid `
            -AccessMask $script:Mask `
            -AceIndex 0 `
            -AceFlagsRaw $script:AfBoth) )
        $records.Add( (New-AceRow `
            -ObjectDN "CN=u1,OU=Users,$script:DomainNc" `
            -ObjectClass 'user' `
            -TrusteeSid $script:TrusteeSid `
            -AccessMask $script:Mask `
            -IsInherited $true `
            -IsDaclProtected $true `
            -AceIndex 0) )

        $anomalies = [List[PSObject]]::new()
        $result = Invoke-Phase5Stream `
            -Records $records `
            -NamingContextDistinguishedNames $script:NcRoots `
            -ProtectedDaclAnomalies $anomalies

        $result.Stats.ProtectedDacl | Should -Be 1
        $result.Stats.Resolved      | Should -Be 0

        $result.Records[1].InheritanceSourceDN   | Should -BeNullOrEmpty
        $result.Records[1].InheritanceSourceNote | Should -Be 'InconsistentProtectedDacl'

        $anomalies.Count       | Should -Be 1
        $anomalies[0].Event    | Should -Be 'InheritedAceOnProtectedDacl'
        $anomalies[0].ObjectDN | Should -Be "CN=u1,OU=Users,$script:DomainNc"
    }

    It 'records SchemaDefaultOrUnresolved when no ancestor matches' {
        $records = [List[PSObject]]::new()
        $records.Add( (New-AceRow `
            -ObjectDN "CN=u1,OU=Users,$script:DomainNc" `
            -ObjectClass 'user' `
            -TrusteeSid $script:TrusteeSid `
            -AccessMask $script:Mask `
            -IsInherited $true `
            -AceIndex 0) )

        $result = Invoke-Phase5Stream `
            -Records $records `
            -NamingContextDistinguishedNames $script:NcRoots

        $result.Stats.Unresolved | Should -Be 1
        $result.Records[0].InheritanceSourceDN   | Should -BeNullOrEmpty
        $result.Records[0].InheritanceSourceNote | Should -Be 'SchemaDefaultOrUnresolved'
    }

    It 'leaves explicit rows un-mutated (InheritanceSourceDN stays empty)' {
        $records = [List[PSObject]]::new()
        $records.Add( (New-AceRow `
            -ObjectDN "OU=Users,$script:DomainNc" `
            -ObjectClass 'organizationalUnit' `
            -TrusteeSid $script:TrusteeSid `
            -AccessMask $script:Mask `
            -AceIndex 0 `
            -AceFlagsRaw $script:AfBoth) )

        $result = Invoke-Phase5Stream `
            -Records $records `
            -NamingContextDistinguishedNames $script:NcRoots

        $result.Stats.InheritedTotal | Should -Be 0
        $result.Records[0].PSObject.Properties['InheritanceSourceDN']   | Should -Not -BeNullOrEmpty
        $result.Records[0].PSObject.Properties['InheritanceSourceNote'] | Should -Not -BeNullOrEmpty
        $result.Records[0].InheritanceSourceDN   | Should -BeNullOrEmpty
        $result.Records[0].InheritanceSourceNote | Should -BeNullOrEmpty
    }

    It 'flushes an output batch when -OutputBatchSize is reached mid-stream' {
        # OutputBatchSize=2 forces the writer to emit one batch every two
        # records, so the inside-loop flush path is exercised even on a
        # small fixture.
        $records = [List[PSObject]]::new()
        foreach ($i in 1..5) {
            $records.Add( (New-AceRow `
                -ObjectDN "CN=u$i,$script:DomainNc" `
                -ObjectClass 'user' `
                -TrusteeSid $script:TrusteeSid `
                -AccessMask $script:Mask `
                -AceIndex 0) )
        }

        $workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("phase5-batch-{0}" -f ([guid]::NewGuid()))
        New-Item -ItemType Directory -Path $workDir -Force | Out-Null
        try {
            $inputPath  = Join-Path $workDir 'phase3.clixml'
            $outputPath = Join-Path $workDir 'phase5.clixml'
            Write-Phase3Fixture -Path $inputPath -Records $records

            $index = New-AceIndexFromStream -Phase3AceRecordsPath $inputPath
            $resolveParams = @{
                Phase3AceRecordsPath            = $inputPath
                Phase5OutputPath                = $outputPath
                AceIndex                        = $index
                NamingContextDistinguishedNames = @($script:DomainNc)
                OutputBatchSize                 = 2
            }
            [void] (Resolve-InheritanceSourceStream @resolveParams)

            $written = Read-Phase5Records -Path $outputPath
            $written.Count | Should -Be 5

            # Three batches expected for five records at size 2 (2+2+1).
            $markerCount = (Select-String -LiteralPath $outputPath -Pattern '<!--===BATCH===-->' -SimpleMatch).Count
            $markerCount | Should -Be 3
        }
        finally {
            Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'emits InheritanceSourceDN/Note columns on Synthetic.Owner and PARSE_ERROR rows uniformly' {
        $records = [List[PSObject]]::new()
        $records.Add( (New-AceRow `
            -ObjectDN "OU=Users,$script:DomainNc" `
            -ObjectClass 'organizationalUnit' `
            -TrusteeSid $script:TrusteeSid `
            -AccessMask 0xE0000 `
            -AceIndex -1) )    # Synthetic.Owner
        $records.Add( (New-AceRow `
            -ObjectDN "OU=Bad,$script:DomainNc" `
            -ObjectClass 'organizationalUnit' `
            -TrusteeSid '' `
            -AccessMask 0 `
            -AceIndex -2) )    # PARSE_ERROR

        $result = Invoke-Phase5Stream `
            -Records $records `
            -NamingContextDistinguishedNames $script:NcRoots

        foreach ($r in $result.Records) {
            $r.PSObject.Properties['InheritanceSourceDN']   | Should -Not -BeNullOrEmpty
            $r.PSObject.Properties['InheritanceSourceNote'] | Should -Not -BeNullOrEmpty
            $r.InheritanceSourceDN   | Should -BeNullOrEmpty
            $r.InheritanceSourceNote | Should -BeNullOrEmpty
        }
    }
}
