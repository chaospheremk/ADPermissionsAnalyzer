#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

using namespace System.Collections.Generic
using namespace System.IO

BeforeAll {
    $script:LibDir = Join-Path $PSScriptRoot '../scripts/lib'
    . (Join-Path $script:LibDir 'Phase6-Output.ps1')

    function New-AceRecord {
        param(
            [Parameter()] [string] $ObjectDN              = 'CN=u1,OU=Users,DC=lab,DC=local',
            [Parameter()] [string] $ObjectClass           = 'user',
            [Parameter()] [guid]   $ObjectGUID            = ([guid]::NewGuid()),
            [Parameter()] [string] $TrusteeSid            = 'S-1-5-21-100-200-300-1001',
            [Parameter()] [uint32] $AccessMask            = 0x20020,
            [Parameter()] [string] $AccessControlType     = 'Allow',
            [Parameter()] [string] $AceType               = 'AccessAllowed',
            [Parameter()] [string] $RightsDecoded         = 'ReadProperty, WriteProperty',
            [Parameter()] [guid]   $ObjectTypeGuid        = ([guid]::Empty),
            [Parameter()] [string] $ObjectTypeName        = '',
            [Parameter()] [string] $ObjectTypeKind        = 'All',
            [Parameter()] [guid]   $InheritedObjectTypeGuid = ([guid]::Empty),
            [Parameter()] [string] $InheritedObjectTypeName = '',
            [Parameter()] [string] $InheritanceFlags      = 'None',
            [Parameter()] [bool]   $IsInherited           = $false,
            [Parameter()] [bool]   $IsDaclProtected       = $false,
            [Parameter()] [int]    $AceIndex              = 0,
            [Parameter()] [byte]   $AceFlagsRaw           = 0,
            [Parameter()] [AllowNull()] $InheritanceSourceDN = $null,
            [Parameter()] [string] $InheritanceSourceNote = ''
        )
        [PSCustomObject]@{
            ObjectDN                = $ObjectDN
            ObjectClass             = $ObjectClass
            ObjectGUID              = $ObjectGUID
            TrusteeSid              = $TrusteeSid
            AccessMask              = $AccessMask
            AccessControlType       = $AccessControlType
            AceType                 = $AceType
            RightsDecoded           = $RightsDecoded
            ObjectTypeGuid          = $ObjectTypeGuid
            ObjectTypeName          = $ObjectTypeName
            ObjectTypeKind          = $ObjectTypeKind
            InheritedObjectTypeGuid = $InheritedObjectTypeGuid
            InheritedObjectTypeName = $InheritedObjectTypeName
            InheritanceFlags        = $InheritanceFlags
            IsInherited             = $IsInherited
            IsDaclProtected         = $IsDaclProtected
            AceIndex                = $AceIndex
            AceFlagsRaw             = $AceFlagsRaw
            InheritanceSourceDN     = $InheritanceSourceDN
            InheritanceSourceNote   = $InheritanceSourceNote
        }
    }

    function New-Trustee {
        param(
            [Parameter(Mandatory)] [AllowEmptyString()] [string] $Sid,
            [Parameter()] [string] $Name              = '',
            [Parameter()] [string] $PrincipalType     = 'User',
            [Parameter()] [AllowNull()] [string] $DistinguishedName = $null
        )
        if ([string]::IsNullOrEmpty($Name)) { $Name = $Sid }
        [PSCustomObject]@{
            Sid               = $Sid
            Name              = $Name
            PrincipalType     = $PrincipalType
            DistinguishedName = $DistinguishedName
        }
    }

    $script:UserSid     = 'S-1-5-21-100-200-300-1001'
    $script:GroupSid    = 'S-1-5-21-100-200-300-2001'
    $script:OwnerSid    = 'S-1-5-21-100-200-300-1500'
    $script:CollectedAt = '2026-05-07T12:00:00.0000000Z'
    $script:DomainNc    = 'DC=lab,DC=local'

    $script:NamingContexts = @(
        [PSCustomObject]@{ DistinguishedName = $script:DomainNc;                                Type = 'Domain' }
        [PSCustomObject]@{ DistinguishedName = "CN=Configuration,$script:DomainNc";              Type = 'Configuration' }
        [PSCustomObject]@{ DistinguishedName = "CN=Schema,CN=Configuration,$script:DomainNc";    Type = 'Schema' }
        [PSCustomObject]@{ DistinguishedName = "DC=DomainDnsZones,$script:DomainNc";             Type = 'DNS' }
    )
}

Describe 'New-CsvFieldEscaper' {
    It 'passes a clean string through unmodified' {
        New-CsvFieldEscaper -Value 'plain' | Should -Be 'plain'
    }

    It 'returns empty for $null' {
        New-CsvFieldEscaper -Value $null | Should -Be ''
    }

    It 'quotes when the value contains a comma' {
        New-CsvFieldEscaper -Value 'a,b' | Should -Be '"a,b"'
    }

    It 'doubles internal double-quotes and quotes the field' {
        New-CsvFieldEscaper -Value 'he said "hi"' | Should -Be '"he said ""hi"""'
    }

    It 'quotes when the value contains LF' {
        New-CsvFieldEscaper -Value "line1`nline2" | Should -Be "`"line1`nline2`""
    }

    It 'quotes when the value contains CR' {
        New-CsvFieldEscaper -Value "x`ry" | Should -Be "`"x`ry`""
    }
}

Describe 'ConvertTo-DetailRow' {
    BeforeAll {
        $script:AceTrustee = New-Trustee -Sid $script:UserSid -Name 'LAB\u1' -PrincipalType 'User' `
            -DistinguishedName 'CN=u1,OU=Users,DC=lab,DC=local'
    }

    It 'emits one field per plan-§11 column in order' {
        # Use a DN without commas so the per-column assertions don't have to
        # account for RFC-4180 quoting on the ObjectDN field.
        $ace = New-AceRecord -TrusteeSid $script:UserSid -ObjectDN 'DC=lab' -ObjectClass 'domain'

        $rowParams = @{
            Ace                = $ace
            AceTrustee         = $script:AceTrustee
            EffectiveTrustee   = $script:AceTrustee
            IsThroughGroup     = $false
            GroupExpansionPath = ''
            NamingContext      = 'Domain'
            CollectedAt        = $script:CollectedAt
        }
        $row = ConvertTo-DetailRow @rowParams

        # Tracks Phase6DetailColumns count (plan §11): 30 columns.
        $row.Length    | Should -Be 30
        $row[0]        | Should -Be 'DC=lab'
        $row[3]        | Should -Be 'Domain'
        $row[4]        | Should -Be $script:UserSid
        # AceTrusteeName 'LAB\u1' has no escape triggers — passes through.
        $row[5]        | Should -Be 'LAB\u1'
        $row[6]        | Should -Be 'User'
        $row[11]       | Should -Be 'False'
        $row[13]       | Should -Be 'AccessAllowed'
        $row[14]       | Should -Be '0'
        $row[15]       | Should -Be 'Allow'
        $row[-1]       | Should -Be $script:CollectedAt
    }

    It 'preserves Synthetic.Owner row shape (AceIndex=-1, OwnerImplicit, Allow)' {
        $ownerAce = New-AceRecord `
            -TrusteeSid $script:OwnerSid `
            -AceType 'Synthetic.Owner' `
            -RightsDecoded 'OwnerImplicit' `
            -AccessMask 0xE0000 `
            -AccessControlType 'Allow' `
            -AceIndex -1
        $ownerTrustee = New-Trustee -Sid $script:OwnerSid -Name 'LAB\owner' -PrincipalType 'User'

        $rowParams = @{
            Ace                = $ownerAce
            AceTrustee         = $ownerTrustee
            EffectiveTrustee   = $ownerTrustee
            IsThroughGroup     = $false
            GroupExpansionPath = ''
            NamingContext      = 'Domain'
            CollectedAt        = $script:CollectedAt
        }
        $row = ConvertTo-DetailRow @rowParams

        $row[13] | Should -Be 'Synthetic.Owner'
        $row[14] | Should -Be '-1'
        $row[15] | Should -Be 'Allow'
        $row[16] | Should -Be 'OwnerImplicit'
    }

    It 'preserves PARSE_ERROR row exception message in ObjectTypeName' {
        $errorAce = New-AceRecord `
            -TrusteeSid '' `
            -AceType 'PARSE_ERROR' `
            -RightsDecoded 'PARSE_ERROR' `
            -AccessMask 0 `
            -AccessControlType '' `
            -AceIndex -2 `
            -ObjectTypeName 'Bad SD: nonsense'

        $emptyTrustee = New-Trustee -Sid '' -Name '' -PrincipalType 'Unknown'

        $rowParams = @{
            Ace                = $errorAce
            AceTrustee         = $emptyTrustee
            EffectiveTrustee   = $emptyTrustee
            IsThroughGroup     = $false
            GroupExpansionPath = ''
            NamingContext      = 'Domain'
            CollectedAt        = $script:CollectedAt
        }
        $row = ConvertTo-DetailRow @rowParams

        $row[13] | Should -Be 'PARSE_ERROR'
        $row[14] | Should -Be '-2'
        $row[19] | Should -Be 'Bad SD: nonsense'
    }

    It 'populates InheritanceSourceDN for inherited rows' {
        # Single-token DN avoids the embedded-comma quoting case exercised in
        # the round-trip test below.
        $aceParams = @{
            IsInherited           = $true
            InheritanceSourceDN   = 'DC=lab'
            InheritanceSourceNote = ''
        }
        $ace = New-AceRecord @aceParams

        $rowParams = @{
            Ace                = $ace
            AceTrustee         = $script:AceTrustee
            EffectiveTrustee   = $script:AceTrustee
            IsThroughGroup     = $false
            GroupExpansionPath = ''
            NamingContext      = 'Domain'
            CollectedAt        = $script:CollectedAt
        }
        $row = ConvertTo-DetailRow @rowParams

        $row[23] | Should -Be 'True'
        $row[25] | Should -Be 'DC=lab'
        $row[26] | Should -Be ''
    }
}

Describe 'Get-EffectiveTrusteeRecord' {
    BeforeEach {
        $script:Cache = [Dictionary[string, PSObject]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
        $script:Expansion = [Dictionary[string, List[PSObject]]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
    }

    It 'returns one direct tuple when the trustee is not a group (no expansion)' {
        $script:Cache[$script:UserSid] = New-Trustee -Sid $script:UserSid -Name 'LAB\u1' -PrincipalType 'User' `
            -DistinguishedName 'CN=u1,OU=Users,DC=lab,DC=local'

        $ace = New-AceRecord -TrusteeSid $script:UserSid

        $params = @{
            Ace                 = $ace
            TrusteeCache        = $script:Cache
            GroupExpansionCache = $script:Expansion
        }
        $tuples = Get-EffectiveTrusteeRecord @params

        $tuples.Count                       | Should -Be 1
        $tuples[0].IsThroughGroup           | Should -BeFalse
        $tuples[0].GroupExpansionPath       | Should -Be ''
        $tuples[0].EffectiveTrustee.Sid     | Should -Be $script:UserSid
    }

    It 'fans out to one tuple per cached transitive member with IsThroughGroup=true' {
        $groupTrustee = New-Trustee -Sid $script:GroupSid -Name 'LAB\Tier0-Admins' -PrincipalType 'Group' `
            -DistinguishedName "CN=Tier0-Admins,OU=Groups,$script:DomainNc"
        $script:Cache[$script:GroupSid] = $groupTrustee

        $member1 = New-Trustee -Sid 'S-1-5-21-100-200-300-1101' -Name 'LAB\m1' -PrincipalType 'User'
        $member2 = New-Trustee -Sid 'S-1-5-21-100-200-300-1102' -Name 'LAB\m2' -PrincipalType 'User'
        $members = [List[PSObject]]::new()
        $members.Add($member1); $members.Add($member2)
        $script:Expansion[$script:GroupSid] = $members

        $ace = New-AceRecord -TrusteeSid $script:GroupSid

        $params = @{
            Ace                 = $ace
            TrusteeCache        = $script:Cache
            GroupExpansionCache = $script:Expansion
        }
        $tuples = Get-EffectiveTrusteeRecord @params

        $tuples.Count                  | Should -Be 2
        $tuples[0].IsThroughGroup      | Should -BeTrue
        $tuples[0].GroupExpansionPath  | Should -Be 'LAB\Tier0-Admins'
        $tuples[0].EffectiveTrustee.Sid | Should -Be 'S-1-5-21-100-200-300-1101'
        $tuples[1].EffectiveTrustee.Sid | Should -Be 'S-1-5-21-100-200-300-1102'
    }

    It 'emits the group itself when no expansion entry exists (terminal-skip path)' {
        # Phase 4 skips terminal SIDs before expanding — they never land in
        # $GroupExpansionCache. Phase 6 must therefore emit the trustee as
        # itself rather than dropping the row.
        $script:Cache[$script:GroupSid] = New-Trustee -Sid $script:GroupSid `
            -Name 'BUILTIN\Administrators' -PrincipalType 'WellKnown'

        $ace = New-AceRecord -TrusteeSid $script:GroupSid

        $params = @{
            Ace                 = $ace
            TrusteeCache        = $script:Cache
            GroupExpansionCache = $script:Expansion
        }
        $tuples = Get-EffectiveTrusteeRecord @params

        $tuples.Count                       | Should -Be 1
        $tuples[0].IsThroughGroup           | Should -BeFalse
        $tuples[0].EffectiveTrustee.Sid     | Should -Be $script:GroupSid
    }

    It 'falls back to a synthetic trustee when the cache misses' {
        $ace = New-AceRecord -TrusteeSid 'S-1-5-21-orphan-9999'

        $params = @{
            Ace                 = $ace
            TrusteeCache        = $script:Cache
            GroupExpansionCache = $script:Expansion
        }
        $tuples = Get-EffectiveTrusteeRecord @params

        $tuples.Count                          | Should -Be 1
        $tuples[0].EffectiveTrustee.Sid        | Should -Be 'S-1-5-21-orphan-9999'
        $tuples[0].EffectiveTrustee.PrincipalType | Should -Be 'Unknown'
    }
}

Describe 'Write-DetailCsv' {
    BeforeAll {
        $script:WorkDir = Join-Path ([Path]::GetTempPath()) ("phase6-test-{0}" -f ([guid]::NewGuid()))
        New-Item -ItemType Directory -Path $script:WorkDir -Force | Out-Null
    }

    AfterAll {
        if (Test-Path -LiteralPath $script:WorkDir) {
            Remove-Item -LiteralPath $script:WorkDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'writes header + body rows and round-trips a field with commas/quotes through Import-Csv' {
        $cache = [Dictionary[string, PSObject]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $cache[$script:UserSid] = New-Trustee -Sid $script:UserSid -Name 'LAB\Smith, John' -PrincipalType 'User' `
            -DistinguishedName 'CN=Smith\, John,OU=Users,DC=lab,DC=local'

        $expansion = [Dictionary[string, List[PSObject]]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)

        # Two ACEs — one with a benign trustee, one whose RightsDecoded contains
        # comma + double-quote so the round-trip exercises the escape path.
        $records = [List[PSObject]]::new()
        $records.Add( (New-AceRecord -TrusteeSid $script:UserSid `
            -RightsDecoded 'ReadProperty, "WriteProperty"' `
            -ObjectTypeName 'a, b "c"') )
        $records.Add( (New-AceRecord -TrusteeSid $script:UserSid `
            -ObjectDN "OU=Tier0,$script:DomainNc" `
            -ObjectClass 'organizationalUnit' `
            -RightsDecoded 'GenericAll' `
            -AccessMask 0xF01FF `
            -AceIndex 1) )

        $detailPath = Join-Path $script:WorkDir 'detail.csv'
        $stats      = [Dictionary[string, PSObject]]::new()

        $writeParams = @{
            DetailPath          = $detailPath
            AceRecords          = $records
            TrusteeCache        = $cache
            GroupExpansionCache = $expansion
            NamingContexts      = $script:NamingContexts
            PivotStats          = $stats
            CollectedAt         = $script:CollectedAt
        }
        $count = Write-DetailCsv @writeParams

        $count                              | Should -Be 2
        Test-Path -LiteralPath $detailPath  | Should -BeTrue

        $imported = Import-Csv -LiteralPath $detailPath
        $imported.Count                                          | Should -Be 2
        $imported[0].RightsDecoded                               | Should -Be 'ReadProperty, "WriteProperty"'
        $imported[0].ObjectTypeName                              | Should -Be 'a, b "c"'
        $imported[0].EffectiveTrusteeName                        | Should -Be 'LAB\Smith, John'
        $imported[0].NamingContext                               | Should -Be 'Domain'
        $imported[0].CollectedAt                                 | Should -Be $script:CollectedAt
    }

    It 'populates $PivotStats with expected counters for every effective trustee' {
        $cache = [Dictionary[string, PSObject]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $expansion = [Dictionary[string, List[PSObject]]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)

        $cache[$script:UserSid]  = New-Trustee -Sid $script:UserSid  -Name 'LAB\u1'    -PrincipalType 'User'
        $cache[$script:GroupSid] = New-Trustee -Sid $script:GroupSid -Name 'LAB\grp'   -PrincipalType 'Group' `
            -DistinguishedName "CN=grp,OU=Groups,$script:DomainNc"

        $member = New-Trustee -Sid 'S-1-5-21-100-200-300-1101' -Name 'LAB\m1' -PrincipalType 'User'
        $list   = [List[PSObject]]::new(); $list.Add($member)
        $expansion[$script:GroupSid] = $list

        $records = [List[PSObject]]::new()
        # 2 direct allow ACEs to the user (one explicit, one inherited)
        $records.Add( (New-AceRecord -TrusteeSid $script:UserSid -RightsDecoded 'ReadProperty' -AceIndex 0) )
        $records.Add( (New-AceRecord -TrusteeSid $script:UserSid -RightsDecoded 'WriteProperty' -AceIndex 1 `
            -IsInherited $true) )
        # 1 deny ACE on a different object to the same user (counts toward distinct objects)
        $records.Add( (New-AceRecord -TrusteeSid $script:UserSid -ObjectDN "CN=u2,OU=Users,$script:DomainNc" `
            -ObjectClass 'user' -RightsDecoded 'WriteDacl' -AccessControlType 'Deny' -AceType 'AccessDenied' `
            -AceIndex 0) )
        # 1 ACE through the group → fans to member m1 with IsThroughGroup=true
        $records.Add( (New-AceRecord -TrusteeSid $script:GroupSid -RightsDecoded 'GenericAll' -AceIndex 0) )

        $detailPath = Join-Path $script:WorkDir 'detail-stats.csv'
        $stats      = [Dictionary[string, PSObject]]::new()

        $writeParams = @{
            DetailPath          = $detailPath
            AceRecords          = $records
            TrusteeCache        = $cache
            GroupExpansionCache = $expansion
            NamingContexts      = $script:NamingContexts
            PivotStats          = $stats
            CollectedAt         = $script:CollectedAt
        }
        $count = Write-DetailCsv @writeParams

        # 3 user rows + 1 expanded member row = 4
        $count | Should -Be 4

        $stats.ContainsKey($script:UserSid)              | Should -BeTrue
        $stats.ContainsKey('S-1-5-21-100-200-300-1101')  | Should -BeTrue
        $stats.ContainsKey($script:GroupSid)             | Should -BeFalse  # group itself never hits pivot when expanded

        $userBucket = $stats[$script:UserSid]
        $userBucket.TotalAceCount        | Should -Be 3
        $userBucket.DirectAceCount       | Should -Be 3
        $userBucket.IndirectAceCount     | Should -Be 0
        $userBucket.AllowAceCount        | Should -Be 2
        $userBucket.DenyAceCount         | Should -Be 1
        $userBucket.ExplicitAceCount     | Should -Be 2
        $userBucket.InheritedAceCount    | Should -Be 1
        $userBucket.DistinctObjectDns.Count | Should -Be 2
        $userBucket.RightsBreakdown['ReadProperty']  | Should -Be 1
        $userBucket.RightsBreakdown['WriteProperty'] | Should -Be 1
        $userBucket.RightsBreakdown['WriteDacl']     | Should -Be 1

        $memberBucket = $stats['S-1-5-21-100-200-300-1101']
        $memberBucket.TotalAceCount       | Should -Be 1
        $memberBucket.IndirectAceCount    | Should -Be 1
        $memberBucket.DirectAceCount      | Should -Be 0
    }
}
