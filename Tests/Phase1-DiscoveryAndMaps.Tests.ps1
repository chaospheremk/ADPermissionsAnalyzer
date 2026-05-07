#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

using namespace System.Collections.Generic
using namespace System.DirectoryServices.Protocols

BeforeAll {
    $script:Phase1Path = Join-Path $PSScriptRoot '../scripts/lib/Phase1-DiscoveryAndMaps.ps1'
    . $script:Phase1Path

    # The map builders type Connection as untyped (ValidateNotNull) so unit
    # tests can pass a sentinel without instantiating a real LdapConnection
    # (whose constructor binds eagerly and fails offline). Production wire-up
    # always passes a real [LdapConnection].
    function New-FakeLdapConnection {
        [PSCustomObject]@{ Sentinel = 'Phase1Test' }
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

    # Real LDAP DirectoryAttribute.GetValues([byte[]]) returns byte[][] —
    # a jagged array where each element is one octet-string value. The map
    # builders read $entry.Attributes[<name>][0] and cast that to [byte[]],
    # so test fixtures must produce the same shape. Pipeline unrolling
    # eats byte[][] returned from a function, so callers inline the cast
    # directly into the hashtable rather than going through a helper.
    function New-OctetFixture {
        param([Parameter(Mandatory)] [guid] $Guid)
        Write-Output -NoEnumerate ([byte[][]] @(, $Guid.ToByteArray()))
    }

    $script:ConfigNc = 'CN=Configuration,DC=lab,DC=local'
    $script:SchemaNc = 'CN=Schema,CN=Configuration,DC=lab,DC=local'
    $script:DefaultNc = 'DC=lab,DC=local'
}

Describe 'New-WellKnownSidMap' {
    It 'returns a Dictionary[string, string] with the canonical universal SIDs' {
        $map = New-WellKnownSidMap

        $map | Should -BeOfType ([Dictionary[string, string]])
        $map['S-1-1-0']  | Should -Be 'Everyone'
        $map['S-1-3-0']  | Should -Be 'CREATOR OWNER'
        $map['S-1-5-9']  | Should -Be 'ENTERPRISE DOMAIN CONTROLLERS'
        $map['S-1-5-10'] | Should -Be 'SELF'
        $map['S-1-5-11'] | Should -Be 'Authenticated Users'
        $map['S-1-5-18'] | Should -Be 'SYSTEM'
    }

    It 'matches SIDs case-insensitively' {
        $map = New-WellKnownSidMap
        $map['s-1-1-0'] | Should -Be 'Everyone'
    }

    It 'omits BUILTIN aliases (S-1-5-32-*) per plan §10' {
        $map = New-WellKnownSidMap
        $builtinKeys = $map.Keys.Where({ $_ -like 'S-1-5-32-*' })
        $builtinKeys.Count | Should -Be 0
    }
}

Describe 'Get-NamingContextType' {
    It 'classifies the default NC as Domain' {
        $params = @{
            NamingContext   = $script:DefaultNc
            DefaultNc       = $script:DefaultNc
            ConfigurationNc = $script:ConfigNc
            SchemaNc        = $script:SchemaNc
        }
        Get-NamingContextType @params | Should -Be 'Domain'
    }

    It 'classifies the Configuration NC' {
        $params = @{
            NamingContext   = $script:ConfigNc
            DefaultNc       = $script:DefaultNc
            ConfigurationNc = $script:ConfigNc
            SchemaNc        = $script:SchemaNc
        }
        Get-NamingContextType @params | Should -Be 'Configuration'
    }

    It 'classifies the Schema NC' {
        $params = @{
            NamingContext   = $script:SchemaNc
            DefaultNc       = $script:DefaultNc
            ConfigurationNc = $script:ConfigNc
            SchemaNc        = $script:SchemaNc
        }
        Get-NamingContextType @params | Should -Be 'Schema'
    }

    It 'classifies DomainDnsZones partition as DNS' {
        $params = @{
            NamingContext   = 'DC=DomainDnsZones,DC=lab,DC=local'
            DefaultNc       = $script:DefaultNc
            ConfigurationNc = $script:ConfigNc
            SchemaNc        = $script:SchemaNc
        }
        Get-NamingContextType @params | Should -Be 'DNS'
    }

    It 'classifies ForestDnsZones partition as DNS' {
        $params = @{
            NamingContext   = 'DC=ForestDnsZones,DC=lab,DC=local'
            DefaultNc       = $script:DefaultNc
            ConfigurationNc = $script:ConfigNc
            SchemaNc        = $script:SchemaNc
        }
        Get-NamingContextType @params | Should -Be 'DNS'
    }

    It 'classifies an unknown NC as Other' {
        $params = @{
            NamingContext   = 'DC=Custom,DC=lab,DC=local'
            DefaultNc       = $script:DefaultNc
            ConfigurationNc = $script:ConfigNc
            SchemaNc        = $script:SchemaNc
        }
        Get-NamingContextType @params | Should -Be 'Other'
    }

    It 'is case-insensitive on the NC comparison' {
        $params = @{
            NamingContext   = 'dc=LAB,dc=local'
            DefaultNc       = $script:DefaultNc
            ConfigurationNc = $script:ConfigNc
            SchemaNc        = $script:SchemaNc
        }
        Get-NamingContextType @params | Should -Be 'Domain'
    }
}

Describe 'New-ADExtendedRightsMap' {
    BeforeEach {
        # Real GUIDs from Microsoft documentation.
        $resetPwGuid    = [guid] '00299570-246d-11d0-a768-00aa006e0529'  # Reset Password (extended right)
        $selfMembership = [guid] 'bf9679c0-0de6-11d0-a285-00aa003049e2'  # Self-Membership (validated write)
        $personalInfo   = [guid] '77b5b886-944a-11d1-aebd-0000f80367c1'  # Personal-Information (property set)
        $unknownMask    = [guid] '11111111-1111-1111-1111-111111111111'

        $script:Entries = [List[hashtable]] @(
            New-LdapEntry -DistinguishedName 'CN=Reset-Password,CN=Extended-Rights,CN=Configuration,DC=lab,DC=local' -Attributes @{
                cn            = @('Reset-Password')
                displayName   = @('Reset Password')
                rightsGuid    = @($resetPwGuid.ToString())
                appliesTo     = @('bf967aba-0de6-11d0-a285-00aa003049e2')
                validAccesses = @('256')
            }
            New-LdapEntry -DistinguishedName 'CN=Self-Membership,CN=Extended-Rights,CN=Configuration,DC=lab,DC=local' -Attributes @{
                cn            = @('Self-Membership')
                displayName   = @('Self Membership')
                rightsGuid    = @($selfMembership.ToString())
                appliesTo     = @('bf967a9c-0de6-11d0-a285-00aa003049e2')
                validAccesses = @('8')
            }
            New-LdapEntry -DistinguishedName 'CN=Personal-Information,CN=Extended-Rights,CN=Configuration,DC=lab,DC=local' -Attributes @{
                cn            = @('Personal-Information')
                displayName   = @('Personal Information')
                rightsGuid    = @($personalInfo.ToString())
                appliesTo     = @('bf967aba-0de6-11d0-a285-00aa003049e2')
                validAccesses = @('48')
            }
            New-LdapEntry -DistinguishedName 'CN=Mystery,CN=Extended-Rights,CN=Configuration,DC=lab,DC=local' -Attributes @{
                cn            = @('Mystery')
                rightsGuid    = @($unknownMask.ToString())
                validAccesses = @('999')
            }
        )

        $script:ExpectedGuids = @{
            ResetPassword       = $resetPwGuid
            SelfMembership      = $selfMembership
            PersonalInformation = $personalInfo
            Unknown             = $unknownMask
        }

        Mock Invoke-PagedLdapSearch { , $script:Entries }
    }

    It 'returns a Dictionary[guid, PSObject]' {
        $callParams = @{
            Connection                 = New-FakeLdapConnection
            ConfigurationNamingContext = $script:ConfigNc
        }
        $map = New-ADExtendedRightsMap @callParams
        $map | Should -BeOfType ([Dictionary[guid, PSObject]])
        $map.Count | Should -Be 4
    }

    It 'classifies validAccesses=256 as ExtendedRight' {
        $callParams = @{
            Connection                 = New-FakeLdapConnection
            ConfigurationNamingContext = $script:ConfigNc
        }
        $map = New-ADExtendedRightsMap @callParams
        $entry = $map[$script:ExpectedGuids.ResetPassword]
        $entry.RightKind     | Should -Be 'ExtendedRight'
        $entry.ValidAccesses | Should -Be 256
        $entry.DisplayName   | Should -Be 'Reset Password'
        $entry.CommonName    | Should -Be 'Reset-Password'
    }

    It 'classifies validAccesses=8 as ValidatedWrite' {
        $callParams = @{
            Connection                 = New-FakeLdapConnection
            ConfigurationNamingContext = $script:ConfigNc
        }
        $map = New-ADExtendedRightsMap @callParams
        $map[$script:ExpectedGuids.SelfMembership].RightKind | Should -Be 'ValidatedWrite'
    }

    It 'classifies validAccesses=48 as PropertySet' {
        $callParams = @{
            Connection                 = New-FakeLdapConnection
            ConfigurationNamingContext = $script:ConfigNc
        }
        $map = New-ADExtendedRightsMap @callParams
        $map[$script:ExpectedGuids.PersonalInformation].RightKind | Should -Be 'PropertySet'
    }

    It 'records unrecognised masks as Unknown rather than dropping them' {
        $callParams = @{
            Connection                 = New-FakeLdapConnection
            ConfigurationNamingContext = $script:ConfigNc
        }
        $map = New-ADExtendedRightsMap @callParams
        $entry = $map[$script:ExpectedGuids.Unknown]
        $entry.RightKind   | Should -Be 'Unknown'
        # Falls back to cn when displayName is missing.
        $entry.DisplayName | Should -Be 'Mystery'
    }
}

Describe 'New-ADSchemaGuidMap' {
    BeforeEach {
        $userGuid = [guid] 'bf967aba-0de6-11d0-a285-00aa003049e2'  # user (classSchema)
        $cnGuid   = [guid] 'bf96793f-0de6-11d0-a285-00aa003049e2'  # cn (attributeSchema)

        $script:Entries = [List[hashtable]] @(
            New-LdapEntry -DistinguishedName 'CN=User,CN=Schema,CN=Configuration,DC=lab,DC=local' -Attributes @{
                lDAPDisplayName = @('user')
                schemaIDGUID    = (New-OctetFixture $userGuid)
                objectClass     = @('top', 'classSchema')
            }
            New-LdapEntry -DistinguishedName 'CN=Common-Name,CN=Schema,CN=Configuration,DC=lab,DC=local' -Attributes @{
                lDAPDisplayName = @('cn')
                schemaIDGUID    = (New-OctetFixture $cnGuid)
                objectClass     = @('top', 'attributeSchema')
            }
        )

        $script:ExpectedGuids = @{ User = $userGuid; Cn = $cnGuid }

        Mock Invoke-PagedLdapSearch { , $script:Entries }
    }

    It 'returns a Dictionary[guid, PSObject]' {
        $callParams = @{
            Connection          = New-FakeLdapConnection
            SchemaNamingContext = $script:SchemaNc
        }
        $map = New-ADSchemaGuidMap @callParams
        $map | Should -BeOfType ([Dictionary[guid, PSObject]])
        $map.Count | Should -Be 2
    }

    It 'tags classSchema entries with ObjectCategory=classSchema' {
        $callParams = @{
            Connection          = New-FakeLdapConnection
            SchemaNamingContext = $script:SchemaNc
        }
        $map = New-ADSchemaGuidMap @callParams
        $entry = $map[$script:ExpectedGuids.User]
        $entry.ObjectCategory  | Should -Be 'classSchema'
        $entry.LdapDisplayName | Should -Be 'user'
    }

    It 'tags attributeSchema entries with ObjectCategory=attributeSchema' {
        $callParams = @{
            Connection          = New-FakeLdapConnection
            SchemaNamingContext = $script:SchemaNc
        }
        $map = New-ADSchemaGuidMap @callParams
        $entry = $map[$script:ExpectedGuids.Cn]
        $entry.ObjectCategory  | Should -Be 'attributeSchema'
        $entry.LdapDisplayName | Should -Be 'cn'
    }
}

Describe 'New-PropertySetMembersMap' {
    BeforeEach {
        $personalInfoSet = [guid] '77b5b886-944a-11d1-aebd-0000f80367c1'  # Personal-Information
        $publicInfoSet   = [guid] 'e48d0154-bcf8-11d1-8702-00c04fb96050'  # Public-Information

        $script:Entries = [List[hashtable]] @(
            New-LdapEntry -DistinguishedName 'CN=Street-Address,CN=Schema,CN=Configuration,DC=lab,DC=local' -Attributes @{
                lDAPDisplayName       = @('streetAddress')
                attributeSecurityGUID = (New-OctetFixture $personalInfoSet)
            }
            New-LdapEntry -DistinguishedName 'CN=Home-Phone,CN=Schema,CN=Configuration,DC=lab,DC=local' -Attributes @{
                lDAPDisplayName       = @('homePhone')
                attributeSecurityGUID = (New-OctetFixture $personalInfoSet)
            }
            New-LdapEntry -DistinguishedName 'CN=Display-Name,CN=Schema,CN=Configuration,DC=lab,DC=local' -Attributes @{
                lDAPDisplayName       = @('displayName')
                attributeSecurityGUID = (New-OctetFixture $publicInfoSet)
            }
        )

        $script:ExpectedGuids = @{ PersonalInfo = $personalInfoSet; PublicInfo = $publicInfoSet }

        Mock Invoke-PagedLdapSearch { , $script:Entries }
    }

    It 'returns a Dictionary[guid, List[string]]' {
        $callParams = @{
            Connection          = New-FakeLdapConnection
            SchemaNamingContext = $script:SchemaNc
        }
        $map = New-PropertySetMembersMap @callParams
        $map | Should -BeOfType ([Dictionary[guid, List[string]]])
        $map.Count | Should -Be 2
    }

    It 'reverse-indexes attributes by their property-set GUID' {
        $callParams = @{
            Connection          = New-FakeLdapConnection
            SchemaNamingContext = $script:SchemaNc
        }
        $map = New-PropertySetMembersMap @callParams

        $personalMembers = $map[$script:ExpectedGuids.PersonalInfo]
        $personalMembers.Count | Should -Be 2
        $personalMembers       | Should -Contain 'streetAddress'
        $personalMembers       | Should -Contain 'homePhone'

        $publicMembers = $map[$script:ExpectedGuids.PublicInfo]
        $publicMembers.Count | Should -Be 1
        $publicMembers[0]    | Should -Be 'displayName'
    }
}

Describe 'Connect-AdLdap parameter resolution' {
    It 'throws when no -Server, no -Domain, and USERDNSDOMAIN is empty' {
        $original = $env:USERDNSDOMAIN
        try {
            $env:USERDNSDOMAIN = ''
            { Connect-AdLdap } | Should -Throw -ExpectedMessage '*USERDNSDOMAIN*'
        }
        finally {
            $env:USERDNSDOMAIN = $original
        }
    }
}
