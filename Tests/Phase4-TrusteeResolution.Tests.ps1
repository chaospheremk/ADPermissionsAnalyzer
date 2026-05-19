#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

using namespace System.Collections.Generic
using namespace System.DirectoryServices.Protocols
using namespace System.Security.Principal

BeforeAll {
    $script:LibDir = Join-Path $PSScriptRoot '../scripts/lib'
    . (Join-Path $script:LibDir 'Phase1-DiscoveryAndMaps.ps1')
    # Phase 3 lib hosts the streaming primitives (Write-AceBatchToStream,
    # Read-AceStream) used by Phase 4's Get-DistinctTrusteeSetFromStream.
    . (Join-Path $script:LibDir 'Phase3-AceParsing.ps1')
    . (Join-Path $script:LibDir 'Phase4-TrusteeResolution.ps1')

    function New-FakeLdapConnection {
        [PSCustomObject]@{ Sentinel = 'Phase4Test' }
    }

    function New-LdapEntry {
        param(
            [Parameter(Mandatory)] [string] $DistinguishedName,
            [Parameter(Mandatory)] [hashtable] $Attributes
        )
        @{
            DistinguishedName = $DistinguishedName
            Attributes        = $Attributes
        }
    }

    # See Phase1-DiscoveryAndMaps.Tests for the byte[][] shape rationale —
    # mocked LDAP fixtures must match what real DirectoryAttribute.GetValues
    # returns: a jagged array of byte[] values.
    function New-OctetFixture {
        param([Parameter(Mandatory)] [byte[]] $Bytes)
        Write-Output -NoEnumerate ([byte[][]] @(, $Bytes))
    }

    function New-SidBytes {
        param([Parameter(Mandatory)] [string] $Sid)
        $sidObj = [SecurityIdentifier]::new($Sid)
        $bytes  = [byte[]]::new($sidObj.BinaryLength)
        $sidObj.GetBinaryForm($bytes, 0)
        , $bytes
    }

    $script:DomainNc       = 'DC=lab,DC=local'
    $script:DomainSid      = 'S-1-5-21-100-200-300'
    $script:TestUserSid    = 'S-1-5-21-100-200-300-1001'
    $script:TestGroupSid   = 'S-1-5-21-100-200-300-1002'
    $script:TestNestedSid  = 'S-1-5-21-100-200-300-1003'
    $script:TestSmsaSid    = 'S-1-5-21-100-200-300-1100'
    $script:TestGmsaSid    = 'S-1-5-21-100-200-300-1101'
    $script:DomainUsersSid = "$script:DomainSid-513"
    $script:OrphanSid      = 'S-1-5-21-999-999-999-1234'
    $script:FspSid         = 'S-1-5-21-555-666-777-500'
}

Describe 'Get-PrincipalTypeFromObjectClass' {
    It 'classifies user' {
        Get-PrincipalTypeFromObjectClass -ObjectClasses @('top', 'person', 'user') |
            Should -Be 'User'
    }

    It 'classifies group' {
        Get-PrincipalTypeFromObjectClass -ObjectClasses @('top', 'group') |
            Should -Be 'Group'
    }

    It 'classifies computer (computer wins over user even though user is in chain)' {
        Get-PrincipalTypeFromObjectClass -ObjectClasses @('top', 'person', 'user', 'computer') |
            Should -Be 'Computer'
    }

    It 'classifies sMSA via msDS-ManagedServiceAccount (not the inherited user/computer)' {
        $classes = @('top', 'person', 'user', 'computer', 'msDS-ManagedServiceAccount')
        Get-PrincipalTypeFromObjectClass -ObjectClasses $classes |
            Should -Be 'ManagedServiceAccount'
    }

    It 'classifies gMSA via msDS-GroupManagedServiceAccount (not the inherited computer)' {
        $classes = @('top', 'person', 'user', 'computer', 'msDS-ManagedServiceAccount', 'msDS-GroupManagedServiceAccount')
        Get-PrincipalTypeFromObjectClass -ObjectClasses $classes |
            Should -Be 'GroupManagedServiceAccount'
    }

    It 'returns Unknown on an empty class list' {
        Get-PrincipalTypeFromObjectClass -ObjectClasses @() | Should -Be 'Unknown'
    }
}

Describe 'New-WellKnownSidSkipSet' {
    It 'includes the universal cross-domain SIDs from plan §10' {
        $set = New-WellKnownSidSkipSet -DomainSid $script:DomainSid
        $set.Contains('S-1-1-0')  | Should -BeTrue   # Everyone
        $set.Contains('S-1-5-7')  | Should -BeTrue   # Anonymous Logon
        $set.Contains('S-1-5-11') | Should -BeTrue   # Authenticated Users
        $set.Contains('S-1-5-9')  | Should -BeTrue   # Enterprise DCs
        $set.Contains('S-1-5-10') | Should -BeTrue   # Self
        $set.Contains('S-1-3-0')  | Should -BeTrue   # Creator Owner
        $set.Contains('S-1-3-1')  | Should -BeTrue   # Creator Group
    }

    It 'resolves the domain RIDs against the supplied domain SID' {
        $set = New-WellKnownSidSkipSet -DomainSid $script:DomainSid
        $set.Contains("$script:DomainSid-513") | Should -BeTrue   # Domain Users
        $set.Contains("$script:DomainSid-516") | Should -BeTrue   # Domain Controllers
        $set.Contains("$script:DomainSid-498") | Should -BeTrue   # Enterprise RODCs
    }

    It 'omits BUILTIN aliases (S-1-5-32-*) — those are matched by prefix in Test-IsTerminalSid' {
        $set = New-WellKnownSidSkipSet -DomainSid $script:DomainSid
        $builtinKeys = $set.Where({ $_ -like 'S-1-5-32-*' })
        $builtinKeys.Count | Should -Be 0
    }

    It 'is case-insensitive' {
        $set = New-WellKnownSidSkipSet -DomainSid $script:DomainSid
        $set.Contains('s-1-1-0') | Should -BeTrue
    }
}

Describe 'Test-IsTerminalSid' {
    BeforeAll {
        $script:SkipSet = New-WellKnownSidSkipSet -DomainSid $script:DomainSid
    }

    It 'returns $true for an explicit skip-set entry (Everyone)' {
        Test-IsTerminalSid -Sid 'S-1-1-0' -SkipSet $script:SkipSet | Should -BeTrue
    }

    It 'returns $true for the runtime-resolved Domain Users RID' {
        Test-IsTerminalSid -Sid $script:DomainUsersSid -SkipSet $script:SkipSet | Should -BeTrue
    }

    It 'returns $true for any S-1-5-32-* alias by prefix' {
        Test-IsTerminalSid -Sid 'S-1-5-32-544' -SkipSet $script:SkipSet | Should -BeTrue   # Administrators
        Test-IsTerminalSid -Sid 'S-1-5-32-545' -SkipSet $script:SkipSet | Should -BeTrue   # Users
    }

    It 'returns $false for an in-domain user SID' {
        Test-IsTerminalSid -Sid $script:TestUserSid -SkipSet $script:SkipSet | Should -BeFalse
    }
}

Describe 'Get-DistinctTrusteeSetFromStream' {
    BeforeAll {
        $script:Phase4StreamDir = Join-Path ([System.IO.Path]::GetTempPath()) ("phase4-stream-{0}" -f ([guid]::NewGuid()))
        New-Item -ItemType Directory -Path $script:Phase4StreamDir -Force | Out-Null

        function Write-AceFixtureFile {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)] [string] $Path,
                [Parameter(Mandatory)] [List[PSObject]] $Records,
                [Parameter()] [int] $BatchSize = 50
            )
            $writer = [System.IO.StreamWriter]::new($Path, $false, [System.Text.UTF8Encoding]::new($false))
            try {
                $buf = [List[PSObject]]::new($BatchSize)
                foreach ($r in $Records) {
                    $buf.Add($r)
                    if ($buf.Count -ge $BatchSize) {
                        Write-AceBatchToStream -Writer $writer -Records $buf
                        $buf.Clear()
                    }
                }
                if ($buf.Count -gt 0) {
                    Write-AceBatchToStream -Writer $writer -Records $buf
                }
                $writer.Flush()
            }
            finally {
                $writer.Dispose()
            }
        }
    }

    AfterAll {
        if (Test-Path -LiteralPath $script:Phase4StreamDir) {
            Remove-Item -LiteralPath $script:Phase4StreamDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'dedupes across DACL ACEs and synthetic-Owner rows, dropping empty TrusteeSid' {
        $records = [List[PSObject]]::new()
        $records.Add([PSCustomObject]@{ TrusteeSid = $script:TestUserSid;  AceType = 'AccessAllowed' })
        $records.Add([PSCustomObject]@{ TrusteeSid = $script:TestUserSid;  AceType = 'AccessAllowed' })   # dup
        $records.Add([PSCustomObject]@{ TrusteeSid = $script:TestGroupSid; AceType = 'AccessAllowed' })
        $records.Add([PSCustomObject]@{ TrusteeSid = $script:TestUserSid;  AceType = 'Synthetic.Owner' }) # owner-row dup
        $records.Add([PSCustomObject]@{ TrusteeSid = '';                   AceType = 'PARSE_ERROR' })   # placeholder

        $path = Join-Path $script:Phase4StreamDir ("distinct-{0}.clixml" -f ([guid]::NewGuid()))
        Write-AceFixtureFile -Path $path -Records $records

        $set = Get-DistinctTrusteeSetFromStream -Phase3AceRecordsPath $path
        $set.Count                          | Should -Be 2
        $set.Contains($script:TestUserSid)  | Should -BeTrue
        $set.Contains($script:TestGroupSid) | Should -BeTrue
    }

    It 'is case-insensitive on SID equality' {
        $records = [List[PSObject]]::new()
        $records.Add([PSCustomObject]@{ TrusteeSid = 'S-1-5-18' })
        $records.Add([PSCustomObject]@{ TrusteeSid = 's-1-5-18' })

        $path = Join-Path $script:Phase4StreamDir ("distinct-ci-{0}.clixml" -f ([guid]::NewGuid()))
        Write-AceFixtureFile -Path $path -Records $records

        $set = Get-DistinctTrusteeSetFromStream -Phase3AceRecordsPath $path
        $set.Count | Should -Be 1
    }

    It 'returns an empty set when the input file does not exist' {
        $missing = Join-Path $script:Phase4StreamDir 'does-not-exist.clixml'
        $set = Get-DistinctTrusteeSetFromStream -Phase3AceRecordsPath $missing
        $set.Count | Should -Be 0
    }

    It 'flattens an array-shaped TrusteeSid into individual entries (BUG-003)' {
        # Defensive contract: nothing in the canonical pipeline produces a
        # multi-valued TrusteeSid (Add-OwnerAce and ConvertFrom-AdAce both
        # set it from a single SecurityIdentifier.Value string). But the
        # Phase C diagnostic captured 845 OrphanSid events whose Message
        # and Data.sid contained the space-joined $OFS representation of
        # an Object[]: somewhere upstream the TrusteeSid column had carried
        # an array, and [HashSet[string]]::Add($array) coerced via $OFS,
        # planting a compound "SID SID SID ..." key into the set. From
        # there it propagated as a single multi-SID "trustee" all the way
        # through OrphanSid emission. Flatten at the streaming reader so
        # each ACE contributes zero-or-more clean SID entries.
        $records = [List[PSObject]]::new()
        $records.Add([PSCustomObject]@{
            TrusteeSid = [Object[]] @('S-1-5-18', 'S-1-5-11', 'S-1-1-0')
            AceType    = 'AccessAllowed'
        })

        $path = Join-Path $script:Phase4StreamDir ("distinct-flatten-{0}.clixml" -f ([guid]::NewGuid()))
        Write-AceFixtureFile -Path $path -Records $records

        $set = Get-DistinctTrusteeSetFromStream -Phase3AceRecordsPath $path

        $set.Count                | Should -Be 3
        $set.Contains('S-1-5-18') | Should -BeTrue
        $set.Contains('S-1-5-11') | Should -BeTrue
        $set.Contains('S-1-1-0')  | Should -BeTrue
        # The space-joined compound key produced by HashSet's $OFS coercion
        # is the BUG-003 fingerprint — it must not appear in the set.
        $set.Contains('S-1-5-18 S-1-5-11 S-1-1-0') | Should -BeFalse
    }
}

Describe 'Resolve-TrusteeSid' {
    BeforeEach {
        $script:Cache           = [Dictionary[string, PSObject]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
        $script:WellKnownSidMap = New-WellKnownSidMap
        $script:Conn            = New-FakeLdapConnection
    }

    It 'short-circuits on cache hit and makes no LSA or LDAP call' {
        $existing = [PSCustomObject]@{
            Sid = $script:TestUserSid; Name = 'CACHED\bob'
            PrincipalType = 'User'; DistinguishedName = 'CN=Bob,DC=lab,DC=local'
        }
        $script:Cache[$script:TestUserSid] = $existing

        Mock Resolve-NTAccount     { throw 'should not be called' }
        Mock Invoke-PagedLdapSearch { throw 'should not be called' }

        $resolveParams = @{
            Sid                 = $script:TestUserSid
            Cache               = $script:Cache
            WellKnownSidMap     = $script:WellKnownSidMap
            Connection          = $script:Conn
            DomainNamingContext = $script:DomainNc
        }
        $result = Resolve-TrusteeSid @resolveParams

        $result.Name | Should -Be 'CACHED\bob'
        Should -Invoke Resolve-NTAccount     -Times 0
        Should -Invoke Invoke-PagedLdapSearch -Times 0
    }

    It 'classifies a Translate result of NT AUTHORITY\SYSTEM as WellKnown without LDAP' {
        Mock Resolve-NTAccount     { 'NT AUTHORITY\SYSTEM' }
        Mock Invoke-PagedLdapSearch { throw 'should not be called for NT AUTHORITY' }

        $resolveParams = @{
            Sid                 = 'S-1-5-18'
            Cache               = $script:Cache
            WellKnownSidMap     = $script:WellKnownSidMap
            Connection          = $script:Conn
            DomainNamingContext = $script:DomainNc
        }
        $result = Resolve-TrusteeSid @resolveParams

        $result.PrincipalType | Should -Be 'WellKnown'
        $result.Name          | Should -Be 'NT AUTHORITY\SYSTEM'
        Should -Invoke Invoke-PagedLdapSearch -Times 0
    }

    It 'falls back to WellKnownSidMap when Translate throws' {
        Mock Resolve-NTAccount { throw [System.Security.Principal.IdentityNotMappedException]::new() }
        # WellKnown lookup should NOT trigger an LDAP call; explicit fail-fast
        # so we know the cascade exited at step 3 before reaching FSP search.
        Mock Invoke-PagedLdapSearch { throw 'should not be called for WellKnown SID' }

        $resolveParams = @{
            Sid                 = 'S-1-5-11'   # Authenticated Users — in static map
            Cache               = $script:Cache
            WellKnownSidMap     = $script:WellKnownSidMap
            Connection          = $script:Conn
            DomainNamingContext = $script:DomainNc
        }
        $result = Resolve-TrusteeSid @resolveParams

        $result.PrincipalType | Should -Be 'WellKnown'
        $result.Name          | Should -Be 'Authenticated Users'
    }

    It 'classifies an in-domain User via Translate + LDAP-by-objectSid lookup' {
        Mock Resolve-NTAccount { 'LAB\bob' }
        Mock Invoke-PagedLdapSearch {
            $entry = New-LdapEntry `
                -DistinguishedName 'CN=Bob,OU=Users,DC=lab,DC=local' `
                -Attributes @{
                    objectClass    = @('top', 'person', 'organizationalPerson', 'user')
                    sAMAccountName = @('bob')
                }
            , [List[hashtable]] @($entry)
        }

        $resolveParams = @{
            Sid                 = $script:TestUserSid
            Cache               = $script:Cache
            WellKnownSidMap     = $script:WellKnownSidMap
            Connection          = $script:Conn
            DomainNamingContext = $script:DomainNc
        }
        $result = Resolve-TrusteeSid @resolveParams

        $result.PrincipalType     | Should -Be 'User'
        $result.Name              | Should -Be 'LAB\bob'
        $result.DistinguishedName | Should -Be 'CN=Bob,OU=Users,DC=lab,DC=local'
        $script:Cache.Count       | Should -Be 1
    }

    It 'classifies CrossDomain when Translate succeeds but the SID is not in the local directory' {
        # Trusted-forest / external principals: the local LSA can resolve the
        # name via SID-history or forest trust, but a SID search of the local
        # directory returns nothing. Distinct from WellKnown and Orphaned.
        Mock Resolve-NTAccount { 'OTHERFOREST\external-user' }
        Mock Invoke-PagedLdapSearch {
            # Empty result set — the SID belongs to a foreign domain.
            , [List[hashtable]]::new()
        }

        $resolveParams = @{
            Sid                 = $script:TestUserSid
            Cache               = $script:Cache
            WellKnownSidMap     = $script:WellKnownSidMap
            Connection          = $script:Conn
            DomainNamingContext = $script:DomainNc
        }
        $result = Resolve-TrusteeSid @resolveParams

        $result.PrincipalType     | Should -Be 'CrossDomain'
        $result.Name              | Should -Be 'OTHERFOREST\external-user'
        $result.DistinguishedName | Should -BeNullOrEmpty
        $script:Cache.Count       | Should -Be 1
    }

    It 'distinguishes sMSA from gMSA via objectClass priority' {
        Mock Resolve-NTAccount { 'LAB\svc-old$' }
        Mock Invoke-PagedLdapSearch {
            $entry = New-LdapEntry `
                -DistinguishedName 'CN=svc-old,CN=Managed Service Accounts,DC=lab,DC=local' `
                -Attributes @{
                    objectClass    = @('top', 'person', 'user', 'computer', 'msDS-ManagedServiceAccount')
                    sAMAccountName = @('svc-old$')
                }
            , [List[hashtable]] @($entry)
        }

        $resolveParams = @{
            Sid                 = $script:TestSmsaSid
            Cache               = $script:Cache
            WellKnownSidMap     = $script:WellKnownSidMap
            Connection          = $script:Conn
            DomainNamingContext = $script:DomainNc
        }
        $result = Resolve-TrusteeSid @resolveParams

        $result.PrincipalType | Should -Be 'ManagedServiceAccount'

        # Now a gMSA — same fixture shape, different terminal class.
        Mock Invoke-PagedLdapSearch {
            $entry = New-LdapEntry `
                -DistinguishedName 'CN=svc-new,CN=Managed Service Accounts,DC=lab,DC=local' `
                -Attributes @{
                    objectClass    = @('top', 'person', 'user', 'computer', 'msDS-ManagedServiceAccount', 'msDS-GroupManagedServiceAccount')
                    sAMAccountName = @('svc-new$')
                }
            , [List[hashtable]] @($entry)
        }

        $gmsaParams = @{
            Sid                 = $script:TestGmsaSid
            Cache               = $script:Cache
            WellKnownSidMap     = $script:WellKnownSidMap
            Connection          = $script:Conn
            DomainNamingContext = $script:DomainNc
        }
        $gmsa = Resolve-TrusteeSid @gmsaParams

        $gmsa.PrincipalType | Should -Be 'GroupManagedServiceAccount'
    }

    It 'classifies an FSP when found under CN=ForeignSecurityPrincipals' {
        Mock Resolve-NTAccount { throw [System.Security.Principal.IdentityNotMappedException]::new() }
        Mock Invoke-PagedLdapSearch -ParameterFilter {
            $SearchBase -like 'CN=ForeignSecurityPrincipals,*'
        } -MockWith {
            $fspDn = "CN=$script:FspSid,CN=ForeignSecurityPrincipals,$script:DomainNc"
            $entry = New-LdapEntry -DistinguishedName $fspDn -Attributes @{
                cn          = @($script:FspSid)
                objectClass = @('top', 'foreignSecurityPrincipal')
            }
            , [List[hashtable]] @($entry)
        }

        $resolveParams = @{
            Sid                 = $script:FspSid
            Cache               = $script:Cache
            WellKnownSidMap     = $script:WellKnownSidMap
            Connection          = $script:Conn
            DomainNamingContext = $script:DomainNc
        }
        $result = Resolve-TrusteeSid @resolveParams

        $result.PrincipalType     | Should -Be 'ForeignSecurityPrincipal'
        $result.DistinguishedName | Should -Be "CN=$script:FspSid,CN=ForeignSecurityPrincipals,$script:DomainNc"
    }

    It 'marks Orphaned when every resolution path fails' {
        Mock Resolve-NTAccount     { throw [System.Security.Principal.IdentityNotMappedException]::new() }
        # Both the FSP and any other LDAP search return empty.
        Mock Invoke-PagedLdapSearch { , [List[hashtable]]::new() }

        $resolveParams = @{
            Sid                 = $script:OrphanSid
            Cache               = $script:Cache
            WellKnownSidMap     = $script:WellKnownSidMap
            Connection          = $script:Conn
            DomainNamingContext = $script:DomainNc
        }
        $result = Resolve-TrusteeSid @resolveParams

        $result.PrincipalType     | Should -Be 'Orphaned'
        $result.Name              | Should -Be $script:OrphanSid
        $result.DistinguishedName | Should -BeNullOrEmpty
    }
}

Describe 'Expand-GroupTransitive' {
    BeforeEach {
        $script:GroupCache = [Dictionary[string, List[PSObject]]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
        $script:Conn = New-FakeLdapConnection
    }

    It 'expands a nested group A -> B -> {user1, user2} via the in-chain matching rule' {
        $user1Sid = 'S-1-5-21-100-200-300-2001'
        $user2Sid = 'S-1-5-21-100-200-300-2002'

        Mock Invoke-PagedLdapSearch -ParameterFilter {
            $Filter -like '*1.2.840.113556.1.4.1941*'
        } -MockWith {
            $entries = [List[hashtable]]::new()
            $entries.Add( (New-LdapEntry `
                -DistinguishedName "CN=Helpdesk-Admins,OU=Groups,$script:DomainNc" `
                -Attributes @{
                    objectClass    = @('top', 'group')
                    sAMAccountName = @('Helpdesk-Admins')
                    objectSid      = (New-OctetFixture -Bytes (New-SidBytes $script:TestNestedSid))
                }) )
            $entries.Add( (New-LdapEntry `
                -DistinguishedName "CN=user1,OU=Users,$script:DomainNc" `
                -Attributes @{
                    objectClass    = @('top', 'person', 'user')
                    sAMAccountName = @('user1')
                    objectSid      = (New-OctetFixture -Bytes (New-SidBytes $user1Sid))
                }) )
            $entries.Add( (New-LdapEntry `
                -DistinguishedName "CN=user2,OU=Users,$script:DomainNc" `
                -Attributes @{
                    objectClass    = @('top', 'person', 'user')
                    sAMAccountName = @('user2')
                    objectSid      = (New-OctetFixture -Bytes (New-SidBytes $user2Sid))
                }) )
            , $entries
        }

        $expandParams = @{
            GroupSid               = $script:TestGroupSid
            GroupDistinguishedName = "CN=Tier0-Admins,OU=Groups,$script:DomainNc"
            Cache                  = $script:GroupCache
            Connection             = $script:Conn
            DomainNamingContext    = $script:DomainNc
        }
        $members = Expand-GroupTransitive @expandParams

        $members.Count | Should -Be 3
        $sids = @($members).ForEach({ $_.Sid }) | Sort-Object
        $sids | Should -Be (@($script:TestNestedSid, $user1Sid, $user2Sid) | Sort-Object)

        # Cache populated under the group's SID for short-circuit on re-call.
        $script:GroupCache.Count | Should -Be 1
        $script:GroupCache.ContainsKey($script:TestGroupSid) | Should -BeTrue
    }

    It 'caps result size at -MaxMembers and emits a truncation warning' {
        Mock Invoke-PagedLdapSearch -ParameterFilter {
            $Filter -like '*1.2.840.113556.1.4.1941*'
        } -MockWith {
            $entries = [List[hashtable]]::new()
            foreach ($i in 1..5) {
                $sid = "S-1-5-21-100-200-300-300$i"
                $entries.Add( (New-LdapEntry `
                    -DistinguishedName "CN=u$i,OU=Users,$script:DomainNc" `
                    -Attributes @{
                        objectClass    = @('top', 'person', 'user')
                        sAMAccountName = @("u$i")
                        objectSid      = (New-OctetFixture -Bytes (New-SidBytes $sid))
                    }) )
            }
            , $entries
        }

        $expandParams = @{
            GroupSid               = $script:TestGroupSid
            GroupDistinguishedName = "CN=Tier0-Admins,OU=Groups,$script:DomainNc"
            Cache                  = $script:GroupCache
            Connection             = $script:Conn
            DomainNamingContext    = $script:DomainNc
            MaxMembers             = 2
        }
        $warnings = $null
        $members  = Expand-GroupTransitive @expandParams -WarningVariable warnings -WarningAction SilentlyContinue

        $members.Count   | Should -Be 2
        $warnings.Count  | Should -BeGreaterThan 0
        $warnings[0].Message | Should -Match 'truncated at -MaxMembers=2'
    }

    It 'returns the cached list and makes no LDAP call on a repeat lookup' {
        $cached = [List[PSObject]] @(
            [PSCustomObject]@{ Sid = 'S-1-5-21-1-2-3-2001'; PrincipalType = 'User'; DistinguishedName = 'CN=u1,DC=lab,DC=local'; Name = 'u1' }
        )
        $script:GroupCache[$script:TestGroupSid] = $cached

        Mock Invoke-PagedLdapSearch { throw 'should not be called for cached group' }

        $expandParams = @{
            GroupSid               = $script:TestGroupSid
            GroupDistinguishedName = "CN=Tier0-Admins,OU=Groups,$script:DomainNc"
            Cache                  = $script:GroupCache
            Connection             = $script:Conn
            DomainNamingContext    = $script:DomainNc
        }
        $members = Expand-GroupTransitive @expandParams

        $members.Count | Should -Be 1
        Should -Invoke Invoke-PagedLdapSearch -Times 0
    }
}

Describe 'Get-DomainSid' {
    It 'returns the domain SID parsed from the objectSid attribute on the domain NC root' {
        $bytes = New-SidBytes $script:DomainSid
        Mock Invoke-PagedLdapSearch {
            $entry = New-LdapEntry -DistinguishedName $script:DomainNc -Attributes @{
                objectSid = (New-OctetFixture -Bytes $bytes)
            }
            , [List[hashtable]] @($entry)
        }

        $sid = Get-DomainSid -Connection (New-FakeLdapConnection) -DomainNamingContext $script:DomainNc
        $sid | Should -Be $script:DomainSid
    }

    It 'throws when the domain NC read returns no entries' {
        Mock Invoke-PagedLdapSearch { , [List[hashtable]]::new() }
        {
            Get-DomainSid -Connection (New-FakeLdapConnection) -DomainNamingContext $script:DomainNc
        } | Should -Throw -ExpectedMessage '*Cannot read objectSid*'
    }
}

Describe 'Skip-set integration: terminal trustees bypass expansion' {
    It 'Domain Users (<domain>-513) and Everyone (S-1-1-0) are reported as terminal' {
        $skipSet = New-WellKnownSidSkipSet -DomainSid $script:DomainSid

        # Caller (Phase 6) shape: gate Expand-GroupTransitive on Test-IsTerminalSid.
        Test-IsTerminalSid -Sid 'S-1-1-0'             -SkipSet $skipSet | Should -BeTrue
        Test-IsTerminalSid -Sid $script:DomainUsersSid -SkipSet $skipSet | Should -BeTrue

        # Negative control: an ordinary group SID is NOT terminal.
        Test-IsTerminalSid -Sid $script:TestGroupSid -SkipSet $skipSet | Should -BeFalse
    }
}
