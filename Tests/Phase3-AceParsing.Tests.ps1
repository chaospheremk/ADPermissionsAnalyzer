#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

using namespace System.Collections.Generic
using namespace System.DirectoryServices
using namespace System.Security.AccessControl
using namespace System.Security.Principal

BeforeAll {
    $script:LibDir       = Join-Path $PSScriptRoot '../scripts/lib'
    $script:Phase3LibPath = (Resolve-Path (Join-Path $script:LibDir 'Phase3-AceParsing.ps1')).Path
    . $script:Phase3LibPath

    function New-AceSpec {
        param(
            [Parameter(Mandatory)] [string] $Sid,
            [Parameter(Mandatory)] $Rights,
            [Parameter()] [string] $Type = 'Allow',
            [Parameter()] [guid] $ObjectType = [guid]::Empty,
            [Parameter()] [guid] $InheritedObjectType = [guid]::Empty,
            [Parameter()] $Inheritance = 'None'
        )
        @{
            Sid                 = $Sid
            Rights              = $Rights
            Type                = $Type
            ObjectType          = $ObjectType
            InheritedObjectType = $InheritedObjectType
            Inheritance         = $Inheritance
        }
    }

    function New-TestSdBytes {
        param(
            [Parameter()] [string] $OwnerSid = 'S-1-5-18',
            [Parameter()] [hashtable[]] $Aces = @(),
            [Parameter()] [bool] $Protected = $false
        )
        $sd = [ActiveDirectorySecurity]::new()
        $sd.SetOwner([SecurityIdentifier]::new($OwnerSid))
        if ($Protected) { $sd.SetAccessRuleProtection($true, $false) }

        foreach ($spec in $Aces) {
            $sid    = [SecurityIdentifier]::new($spec.Sid)
            $rights = [ActiveDirectoryRights] $spec.Rights
            $type   = [AccessControlType] $spec.Type
            $inh    = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $spec.Inheritance
            $objType = [guid] $spec.ObjectType
            $inhType = [guid] $spec.InheritedObjectType

            $hasInhType = $inhType -ne [guid]::Empty
            $hasObjType = $objType -ne [guid]::Empty

            $rule = $null
            if ($hasInhType) {
                $rule = [ActiveDirectoryAccessRule]::new(
                    $sid, $rights, $type, $objType, $inh, $inhType)
            }
            elseif ($hasObjType) {
                $rule = [ActiveDirectoryAccessRule]::new(
                    $sid, $rights, $type, $objType, $inh)
            }
            else {
                $rule = [ActiveDirectoryAccessRule]::new(
                    $sid, $rights, $type, $inh)
            }
            $sd.AddAccessRule($rule)
        }

        $sd.GetSecurityDescriptorBinaryForm()
    }

    function New-EmptyExtendedRightsMap {
        [Dictionary[guid, PSObject]]::new()
    }

    function New-EmptySchemaGuidMap {
        [Dictionary[guid, PSObject]]::new()
    }

    # Stable fixture GUIDs — fake but consistent across tests so we can wire
    # them into both the SD and the maps.
    $script:GuidProperty     = [guid] '11111111-1111-1111-1111-111111111111'
    $script:GuidPropertySet  = [guid] '22222222-2222-2222-2222-222222222222'
    $script:GuidExtRight     = [guid] '33333333-3333-3333-3333-333333333333'
    $script:GuidClassChild   = [guid] '44444444-4444-4444-4444-444444444444'
    $script:GuidUnmapped     = [guid] '55555555-5555-5555-5555-555555555555'
    $script:GuidInheritClass = [guid] '66666666-6666-6666-6666-666666666666'
}

Describe 'ConvertFrom-NtSecurityDescriptor' {
    It 'parses Owner from a known SD byte[]' {
        $bytes = New-TestSdBytes -OwnerSid 'S-1-5-18'
        $parsed = ConvertFrom-NtSecurityDescriptor -BinaryForm $bytes

        $parsed.Owner | Should -BeOfType ([SecurityIdentifier])
        $parsed.Owner.Value | Should -Be 'S-1-5-18'
    }

    It 'reports IsDaclProtected = $true when SE_DACL_PROTECTED is set' {
        $aces  = @( (New-AceSpec -Sid 'S-1-5-18' -Rights 'GenericAll') )
        $bytes = New-TestSdBytes -Aces $aces -Protected $true
        $parsed = ConvertFrom-NtSecurityDescriptor -BinaryForm $bytes

        $parsed.IsDaclProtected | Should -BeTrue
    }

    It 'reports IsDaclProtected = $false on a non-protected SD' {
        $aces  = @( (New-AceSpec -Sid 'S-1-5-18' -Rights 'GenericAll') )
        $bytes = New-TestSdBytes -Aces $aces -Protected $false
        $parsed = ConvertFrom-NtSecurityDescriptor -BinaryForm $bytes

        $parsed.IsDaclProtected | Should -BeFalse
    }

    It 'returns the ActiveDirectorySecurity as the Dacl member' {
        $bytes = New-TestSdBytes
        $parsed = ConvertFrom-NtSecurityDescriptor -BinaryForm $bytes
        $parsed.Dacl | Should -BeOfType ([ActiveDirectorySecurity])
    }
}

Describe 'Add-OwnerAce' {
    It 'emits a synthetic Owner ACE with AceIndex = -1' {
        $params = @{
            OwnerSid        = [SecurityIdentifier]::new('S-1-5-21-1-2-3-500')
            ObjectDN        = 'OU=Test,DC=lab,DC=local'
            ObjectClass     = 'organizationalUnit'
            ObjectGUID      = [guid] '12345678-1234-1234-1234-123456789abc'
            IsDaclProtected = $false
        }
        $row = Add-OwnerAce @params

        $row.AceType    | Should -Be 'Synthetic.Owner'
        $row.AceIndex   | Should -Be -1
        $row.TrusteeSid | Should -Be 'S-1-5-21-1-2-3-500'
    }

    It 'sets RightsDecoded = OwnerImplicit and AccessMask = (RC|WD|WO)' {
        $params = @{
            OwnerSid        = [SecurityIdentifier]::new('S-1-5-18')
            ObjectDN        = 'CN=u,DC=lab,DC=local'
            ObjectClass     = 'user'
            ObjectGUID      = [guid]::NewGuid()
            IsDaclProtected = $false
        }
        $row = Add-OwnerAce @params

        $row.RightsDecoded     | Should -Be 'OwnerImplicit'
        $row.AccessControlType | Should -Be 'Allow'
        # ReadControl 0x20000 + WriteDacl 0x40000 + WriteOwner 0x80000 = 0xE0000 = 917504
        $row.AccessMask | Should -Be ([uint32] 917504)
    }

    It 'carries IsDaclProtected through from the parent' {
        $params = @{
            OwnerSid        = [SecurityIdentifier]::new('S-1-5-18')
            ObjectDN        = 'CN=u,DC=lab,DC=local'
            ObjectClass     = 'user'
            ObjectGUID      = [guid]::NewGuid()
            IsDaclProtected = $true
        }
        $row = Add-OwnerAce @params

        $row.IsDaclProtected | Should -BeTrue
        $row.IsInherited     | Should -BeFalse
    }
}

Describe 'ConvertFrom-AdAce' {
    BeforeAll {
        function Get-OneRule {
            param(
                [Parameter(Mandatory)] [hashtable] $AceSpec
            )
            $bytes  = New-TestSdBytes -Aces @($AceSpec)
            $parsed = ConvertFrom-NtSecurityDescriptor -BinaryForm $bytes
            $rules  = $parsed.Dacl.GetAccessRules($true, $true, [SecurityIdentifier])
            $rules[0]
        }

        function Invoke-Decode {
            param(
                [Parameter(Mandatory)] [ActiveDirectoryAccessRule] $Rule,
                [Parameter()] [int] $AceIndex = 0,
                [Parameter()] [bool] $IsDaclProtected = $false
            )
            $params = @{
                Rule              = $Rule
                AceIndex          = $AceIndex
                ObjectDN          = 'CN=test,DC=lab,DC=local'
                ObjectClass       = 'user'
                ObjectGUID        = [guid] 'aabbccdd-0000-0000-0000-000000000001'
                IsDaclProtected   = $IsDaclProtected
                ExtendedRightsMap = $script:ExtMap
                SchemaGuidMap     = $script:SchemaMap
            }
            ConvertFrom-AdAce @params
        }
    }

    BeforeEach {
        $script:ExtMap    = New-EmptyExtendedRightsMap
        $script:SchemaMap = New-EmptySchemaGuidMap

        # Wire fixture maps consistent with $script:Guid* constants.
        $script:ExtMap[$script:GuidExtRight] = [PSCustomObject]@{
            DisplayName   = 'Reset-Password'
            CommonName    = 'Reset-Password'
            AppliesTo     = @()
            ValidAccesses = 256
            RightKind     = 'ExtendedRight'
        }
        $script:ExtMap[$script:GuidPropertySet] = [PSCustomObject]@{
            DisplayName   = 'Personal-Information'
            CommonName    = 'Personal-Information'
            AppliesTo     = @()
            ValidAccesses = 48
            RightKind     = 'PropertySet'
        }
        $script:SchemaMap[$script:GuidProperty] = [PSCustomObject]@{
            LdapDisplayName = 'telephoneNumber'
            ObjectCategory  = 'attributeSchema'
        }
        $script:SchemaMap[$script:GuidClassChild] = [PSCustomObject]@{
            LdapDisplayName = 'computer'
            ObjectCategory  = 'classSchema'
        }
        $script:SchemaMap[$script:GuidInheritClass] = [PSCustomObject]@{
            LdapDisplayName = 'user'
            ObjectCategory  = 'classSchema'
        }
    }

    It 'emits comma-decomposed RightsDecoded for GenericAll' {
        $rule = Get-OneRule -AceSpec (New-AceSpec -Sid 'S-1-5-18' -Rights 'GenericAll')
        $row  = Invoke-Decode -Rule $rule

        $row.RightsDecoded | Should -Be 'GenericAll'
        $row.AccessMask    | Should -Be ([uint32] 983551)
    }

    It 'classifies a single-attribute ACE as ObjectTypeKind = Property' {
        $rule = Get-OneRule -AceSpec (
            New-AceSpec -Sid 'S-1-5-18' -Rights 'WriteProperty' -ObjectType $script:GuidProperty)
        $row  = Invoke-Decode -Rule $rule

        $row.ObjectTypeKind | Should -Be 'Property'
        $row.ObjectTypeName | Should -Be 'telephoneNumber'
        $row.ObjectTypeGuid | Should -Be $script:GuidProperty
    }

    It 'classifies a property-set ACE as ObjectTypeKind = PropertySet' {
        $rule = Get-OneRule -AceSpec (
            New-AceSpec -Sid 'S-1-5-18' -Rights 'WriteProperty' -ObjectType $script:GuidPropertySet)
        $row  = Invoke-Decode -Rule $rule

        $row.ObjectTypeKind | Should -Be 'PropertySet'
        $row.ObjectTypeName | Should -Be 'Personal-Information'
    }

    It 'classifies a CreateChild ACE as ObjectTypeKind = ClassChild' {
        $rule = Get-OneRule -AceSpec (
            New-AceSpec -Sid 'S-1-5-18' -Rights 'CreateChild' -ObjectType $script:GuidClassChild)
        $row  = Invoke-Decode -Rule $rule

        $row.ObjectTypeKind | Should -Be 'ClassChild'
        $row.ObjectTypeName | Should -Be 'computer'
    }

    It 'classifies an ExtendedRight ACE as ObjectTypeKind = ExtendedRight' {
        $rule = Get-OneRule -AceSpec (
            New-AceSpec -Sid 'S-1-5-18' -Rights 'ExtendedRight' -ObjectType $script:GuidExtRight)
        $row  = Invoke-Decode -Rule $rule

        $row.ObjectTypeKind | Should -Be 'ExtendedRight'
        $row.ObjectTypeName | Should -Be 'Reset-Password'
    }

    It 'classifies a zero-GUID ACE as ObjectTypeKind = All' {
        $rule = Get-OneRule -AceSpec (New-AceSpec -Sid 'S-1-5-18' -Rights 'GenericRead')
        $row  = Invoke-Decode -Rule $rule

        $row.ObjectTypeKind | Should -Be 'All'
        $row.ObjectTypeGuid | Should -Be ([guid]::Empty)
    }

    It 'classifies an unmapped ObjectType GUID as Unresolved' {
        $rule = Get-OneRule -AceSpec (
            New-AceSpec -Sid 'S-1-5-18' -Rights 'WriteProperty' -ObjectType $script:GuidUnmapped)
        $row  = Invoke-Decode -Rule $rule

        $row.ObjectTypeKind | Should -Be 'Unresolved'
        $row.ObjectTypeGuid | Should -Be $script:GuidUnmapped
    }

    It 'resolves InheritedObjectType via SchemaGuidMap (classSchema)' {
        $aceSpecParams = @{
            Sid                 = 'S-1-5-18'
            Rights              = 'WriteProperty'
            ObjectType          = $script:GuidProperty
            InheritedObjectType = $script:GuidInheritClass
            Inheritance         = 'All'
        }
        $aceSpec = New-AceSpec @aceSpecParams
        $rule    = Get-OneRule -AceSpec $aceSpec
        $row     = Invoke-Decode -Rule $rule

        $row.InheritedObjectTypeGuid | Should -Be $script:GuidInheritClass
        $row.InheritedObjectTypeName | Should -Be 'user'
    }

    It 'preserves AceIndex (0-based ordinal)' {
        $rule = Get-OneRule -AceSpec (New-AceSpec -Sid 'S-1-5-18' -Rights 'GenericRead')
        $row  = Invoke-Decode -Rule $rule -AceIndex 7

        $row.AceIndex | Should -Be 7
    }

    It 'sets AceType = AccessAllowed for plain ACEs' {
        $rule = Get-OneRule -AceSpec (New-AceSpec -Sid 'S-1-5-18' -Rights 'GenericRead')
        $row  = Invoke-Decode -Rule $rule

        $row.AceType | Should -Be 'AccessAllowed'
    }

    It 'sets AceType = AccessAllowedObject when ObjectType is non-empty' {
        $rule = Get-OneRule -AceSpec (
            New-AceSpec -Sid 'S-1-5-18' -Rights 'WriteProperty' -ObjectType $script:GuidProperty)
        $row  = Invoke-Decode -Rule $rule

        $row.AceType | Should -Be 'AccessAllowedObject'
    }

    It 'sets AceType = AccessDeniedObject for deny ACEs with ObjectType' {
        $rule = Get-OneRule -AceSpec (
            New-AceSpec -Sid 'S-1-5-18' -Rights 'WriteProperty' -Type 'Deny' -ObjectType $script:GuidProperty)
        $row  = Invoke-Decode -Rule $rule

        $row.AceType           | Should -Be 'AccessDeniedObject'
        $row.AccessControlType | Should -Be 'Deny'
    }

    It 'composes AceFlagsRaw from inheritance + propagation flags' {
        # ActiveDirectorySecurityInheritance.Descendents -> ContainerInherit (0x02)
        # + InheritOnly (0x08) = 0x0A.
        $aceSpec = New-AceSpec -Sid 'S-1-5-18' -Rights 'GenericRead' -Inheritance 'Descendents'
        $rule    = Get-OneRule -AceSpec $aceSpec
        $row     = Invoke-Decode -Rule $rule

        $row.AceFlagsRaw | Should -Be ([byte] 0x0A)
    }

    It 'propagates IsDaclProtected from the parent flag' {
        $rule = Get-OneRule -AceSpec (New-AceSpec -Sid 'S-1-5-18' -Rights 'GenericRead')
        $row  = Invoke-Decode -Rule $rule -IsDaclProtected $true

        $row.IsDaclProtected | Should -BeTrue
    }
}

Describe 'Invoke-AceParsingWorkUnit' {
    BeforeEach {
        $script:ExtMap    = New-EmptyExtendedRightsMap
        $script:SchemaMap = New-EmptySchemaGuidMap
    }

    It 'returns synthetic Owner ACE plus DACL ACEs for each object' {
        $aces = @(
            (New-AceSpec -Sid 'S-1-5-18' -Rights 'GenericRead')
            (New-AceSpec -Sid 'S-1-5-11' -Rights 'GenericAll')
        )
        $bytes = New-TestSdBytes -OwnerSid 'S-1-5-18' -Aces $aces

        $batch = [List[PSObject]]::new()
        $batch.Add([PSCustomObject]@{
            DistinguishedName     = 'CN=u0,DC=lab,DC=local'
            StructuralObjectClass = 'user'
            ObjectGUID            = [guid] '12345678-1234-1234-1234-123456789abc'
            NTSecurityDescriptor  = $bytes
        })

        $params = @{
            Batch                 = $batch
            ExtendedRightsMap = $script:ExtMap
            SchemaGuidMap     = $script:SchemaMap
        }
        $records = Invoke-AceParsingWorkUnit @params

        # Expect 1 owner + 2 DACL = 3 records.
        $records.Count | Should -Be 3
        ($records.Where({ $_.AceType -eq 'Synthetic.Owner' })).Count | Should -Be 1

        $synthetic = ($records.Where({ $_.AceType -eq 'Synthetic.Owner' }))[0]
        $synthetic.AceIndex | Should -Be -1

        $daclRows = $records.Where({ $_.AceType -ne 'Synthetic.Owner' })
        $daclRows.Count | Should -Be 2
        $indices = $daclRows.ForEach({ $_.AceIndex }) | Sort-Object
        $indices | Should -Be @(0, 1)
    }

    It 'emits PARSE_ERROR for an object with a null NTSecurityDescriptor' {
        # Phase 2 sets NTSecurityDescriptor = $null for objects the running
        # account cannot read DACLs on (and schema-only objects). Phase 3
        # must isolate that via the same PARSE_ERROR placeholder path, not
        # abort the batch.
        $batch = [List[PSObject]]::new()
        $batch.Add([PSCustomObject]@{
            DistinguishedName     = 'CN=null-sd,DC=lab,DC=local'
            StructuralObjectClass = 'user'
            ObjectGUID            = [guid]::Empty
            NTSecurityDescriptor  = $null
        })

        $params = @{
            Batch             = $batch
            ExtendedRightsMap = $script:ExtMap
            SchemaGuidMap     = $script:SchemaMap
        }
        $records = Invoke-AceParsingWorkUnit @params

        $records.Count                          | Should -Be 1
        $records[0].AceType                     | Should -Be 'PARSE_ERROR'
        $records[0].AceIndex                    | Should -Be -2
        $records[0].ObjectDN                    | Should -Be 'CN=null-sd,DC=lab,DC=local'
        # The catch path carries the underlying exception text into
        # ObjectTypeName so an operator can diagnose from the CSV alone.
        $records[0].ObjectTypeName              | Should -Not -BeNullOrEmpty
    }

    It 'isolates per-object parse failures with a PARSE_ERROR placeholder' {
        $bytes = New-TestSdBytes -OwnerSid 'S-1-5-18' -Aces @(
            (New-AceSpec -Sid 'S-1-5-18' -Rights 'GenericRead'))

        $batch = [List[PSObject]]::new()
        # Bad object — corrupt SD bytes.
        $batch.Add([PSCustomObject]@{
            DistinguishedName     = 'CN=bad,DC=lab,DC=local'
            StructuralObjectClass = 'user'
            ObjectGUID            = [guid]::Empty
            NTSecurityDescriptor  = [byte[]] (1, 2, 3)
        })
        # Good object — should parse normally.
        $batch.Add([PSCustomObject]@{
            DistinguishedName     = 'CN=ok,DC=lab,DC=local'
            StructuralObjectClass = 'user'
            ObjectGUID            = [guid]::NewGuid()
            NTSecurityDescriptor  = $bytes
        })

        $params = @{
            Batch                 = $batch
            ExtendedRightsMap = $script:ExtMap
            SchemaGuidMap     = $script:SchemaMap
        }
        $records = Invoke-AceParsingWorkUnit @params

        $errorRows = $records.Where({ $_.AceType -eq 'PARSE_ERROR' })
        $errorRows.Count | Should -Be 1
        $errorRows[0].AceIndex | Should -Be -2
        $errorRows[0].ObjectDN | Should -Be 'CN=bad,DC=lab,DC=local'

        # The good object still produces records.
        ($records.Where({ $_.ObjectDN -eq 'CN=ok,DC=lab,DC=local' })).Count |
            Should -BeGreaterThan 0
    }
}

Describe 'New-RunspacePool / Invoke-RunspacePoolWork' {
    It 'aggregates results from a parallel run' {
        $pool = New-RunspacePool -ThreadCount 2
        try {
            $work    = { param($x) [PSCustomObject]@{ Doubled = $x * 2 } }
            $bag     = [List[PSObject]]::new()
            $params  = @{
                Pool     = $pool
                WorkUnit = $work
                Inputs   = @(1, 2, 3, 4, 5)
                ErrorBag = $bag
            }
            $results = Invoke-RunspacePoolWork @params

            $results.Count | Should -Be 5
            $values = @($results).ForEach({ $_.Doubled }) | Sort-Object
            $values | Should -Be @(2, 4, 6, 8, 10)
            $bag.Count | Should -Be 0
        }
        finally {
            $pool.Close()
            $pool.Dispose()
        }
    }

    It 'captures BatchError without throwing on a per-input failure' {
        $pool = New-RunspacePool -ThreadCount 2
        try {
            $work = {
                param($x)
                if ($x -eq 'fail') { throw 'simulated failure' }
                [PSCustomObject]@{ Value = $x }
            }
            $bag    = [List[PSObject]]::new()
            $params = @{
                Pool     = $pool
                WorkUnit = $work
                Inputs   = @('a', 'fail', 'b')
                ErrorBag = $bag
            }
            $results = Invoke-RunspacePoolWork @params

            $results.Count | Should -Be 2
            $bag.Count     | Should -Be 1
            $bag[0].Event  | Should -Be 'BatchError'
            $bag[0].Error  | Should -Match 'simulated failure'
        }
        finally {
            $pool.Close()
            $pool.Dispose()
        }
    }

    It 'injects -Variables as session-state into each runspace' {
        $payload = [PSCustomObject]@{ Token = 'preloaded-fixture' }
        $params  = @{
            ThreadCount = 1
            Variables   = @{ Fixture = $payload }
        }
        $pool = New-RunspacePool @params
        try {
            $work = { param($_) $Fixture.Token }
            $bag  = [List[PSObject]]::new()
            $invokeParams = @{
                Pool     = $pool
                WorkUnit = $work
                Inputs   = @(1)
                ErrorBag = $bag
            }
            $results = Invoke-RunspacePoolWork @invokeParams

            $results[0] | Should -Be 'preloaded-fixture'
        }
        finally {
            $pool.Close()
            $pool.Dispose()
        }
    }

    It 'loads StartupScripts so dot-sourced functions are in scope' {
        $params = @{
            ThreadCount    = 1
            StartupScripts = @($script:Phase3LibPath)
        }
        $pool = New-RunspacePool @params
        try {
            $work = {
                param($_)
                $sd = [System.DirectoryServices.ActiveDirectorySecurity]::new()
                $sd.SetOwner([System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
                $bytes = $sd.GetSecurityDescriptorBinaryForm()
                (ConvertFrom-NtSecurityDescriptor -BinaryForm $bytes).Owner.Value
            }
            $bag = [List[PSObject]]::new()
            $invokeParams = @{
                Pool     = $pool
                WorkUnit = $work
                Inputs   = @(1)
                ErrorBag = $bag
            }
            $results = Invoke-RunspacePoolWork @invokeParams

            $results[0] | Should -Be 'S-1-5-18'
        }
        finally {
            $pool.Close()
            $pool.Dispose()
        }
    }
}
