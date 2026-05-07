#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

using namespace System.Collections.Generic
using namespace System.Security.AccessControl

BeforeAll {
    $script:LibDir = Join-Path $PSScriptRoot '../scripts/lib'
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
        [PSCustomObject]@{
            ObjectDN                = $ObjectDN
            ObjectClass             = $ObjectClass
            TrusteeSid              = $TrusteeSid
            AccessMask              = $AccessMask
            ObjectTypeGuid          = $ObjectTypeGuid
            InheritedObjectTypeName = $InheritedObjectTypeName
            IsInherited             = $IsInherited
            IsDaclProtected         = $IsDaclProtected
            AceIndex                = $AceIndex
            AceFlagsRaw             = $AceFlagsRaw
        }
    }

    $script:DomainNc   = 'DC=lab,DC=local'
    $script:TrusteeSid = 'S-1-5-21-100-200-300-1001'
    $script:Mask       = [uint32] 0x20020   # ReadProperty | WriteProperty (sample)
}

Describe 'New-AceIndex' {
    It 'indexes explicit rows by composite key' {
        $records = [List[PSObject]]::new()
        $records.Add( (New-AceRow `
            -ObjectDN "OU=Users,$script:DomainNc" `
            -ObjectClass 'organizationalUnit' `
            -TrusteeSid $script:TrusteeSid `
            -AccessMask $script:Mask `
            -AceFlagsRaw $script:AfBoth) )

        $index = New-AceIndex -AceRecords $records
        $index.Count | Should -Be 1

        $key = [ValueTuple[string, string, uint32, guid]]::new(
            "OU=USERS,$($script:DomainNc.ToUpperInvariant())",
            $script:TrusteeSid, $script:Mask, [guid]::Empty)
        $index.ContainsKey($key) | Should -BeTrue
        $index[$key].Count        | Should -Be 1
    }

    It 'skips inherited rows (IsInherited = true)' {
        $records = [List[PSObject]]::new()
        $records.Add( (New-AceRow `
            -ObjectDN "CN=u1,OU=Users,$script:DomainNc" `
            -ObjectClass 'user' `
            -TrusteeSid $script:TrusteeSid `
            -AccessMask $script:Mask `
            -IsInherited $true) )

        $index = New-AceIndex -AceRecords $records
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

        $index = New-AceIndex -AceRecords $records
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

        $index = New-AceIndex -AceRecords $records
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

Describe 'Resolve-InheritanceSource' {
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

        $index = New-AceIndex -AceRecords $records
        $stats = Resolve-InheritanceSource `
            -AceRecords $records `
            -AceIndex $index `
            -NamingContextDistinguishedNames $script:NcRoots

        $stats.InheritedTotal | Should -Be 1
        $stats.Resolved        | Should -Be 1
        $stats.Unresolved      | Should -Be 0
        $stats.ProtectedDacl   | Should -Be 0

        $records[1].InheritanceSourceDN   | Should -Be "OU=Users,$script:DomainNc"
        $records[1].InheritanceSourceNote | Should -BeNullOrEmpty
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

        $index = New-AceIndex -AceRecords $records
        $stats = Resolve-InheritanceSource `
            -AceRecords $records `
            -AceIndex $index `
            -NamingContextDistinguishedNames $script:NcRoots

        $stats.Resolved | Should -Be 1
        $records[0].InheritanceSourceDN | Should -Be $script:DomainNc
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

        $index = New-AceIndex -AceRecords $records
        $anomalies = [List[PSObject]]::new()

        $stats = Resolve-InheritanceSource `
            -AceRecords $records `
            -AceIndex $index `
            -NamingContextDistinguishedNames $script:NcRoots `
            -ProtectedDaclAnomalies $anomalies

        $stats.ProtectedDacl | Should -Be 1
        $stats.Resolved      | Should -Be 0

        $records[1].InheritanceSourceDN   | Should -BeNullOrEmpty
        $records[1].InheritanceSourceNote | Should -Be 'InconsistentProtectedDacl'

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

        $index = New-AceIndex -AceRecords $records
        $stats = Resolve-InheritanceSource `
            -AceRecords $records `
            -AceIndex $index `
            -NamingContextDistinguishedNames $script:NcRoots

        $stats.Unresolved | Should -Be 1
        $records[0].InheritanceSourceDN   | Should -BeNullOrEmpty
        $records[0].InheritanceSourceNote | Should -Be 'SchemaDefaultOrUnresolved'
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

        $index = New-AceIndex -AceRecords $records
        $stats = Resolve-InheritanceSource `
            -AceRecords $records `
            -AceIndex $index `
            -NamingContextDistinguishedNames $script:NcRoots

        $stats.InheritedTotal | Should -Be 0
        $records[0].PSObject.Properties['InheritanceSourceDN']   | Should -Not -BeNullOrEmpty
        $records[0].PSObject.Properties['InheritanceSourceNote'] | Should -Not -BeNullOrEmpty
        $records[0].InheritanceSourceDN   | Should -BeNullOrEmpty
        $records[0].InheritanceSourceNote | Should -BeNullOrEmpty
    }

    It 'adds InheritanceSourceDN/Note columns to Synthetic.Owner and PARSE_ERROR rows uniformly' {
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

        $index = New-AceIndex -AceRecords $records
        Resolve-InheritanceSource `
            -AceRecords $records `
            -AceIndex $index `
            -NamingContextDistinguishedNames $script:NcRoots | Out-Null

        foreach ($r in $records) {
            $r.PSObject.Properties['InheritanceSourceDN']   | Should -Not -BeNullOrEmpty
            $r.PSObject.Properties['InheritanceSourceNote'] | Should -Not -BeNullOrEmpty
            $r.InheritanceSourceDN   | Should -BeNullOrEmpty
            $r.InheritanceSourceNote | Should -BeNullOrEmpty
        }
    }
}
