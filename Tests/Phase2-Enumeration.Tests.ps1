#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

using namespace System.Collections.Generic
using namespace System.DirectoryServices.Protocols

BeforeAll {
    $script:LibDir = Join-Path $PSScriptRoot '../scripts/lib'
    . (Join-Path $script:LibDir 'Phase1-DiscoveryAndMaps.ps1')
    . (Join-Path $script:LibDir 'Phase2-Enumeration.ps1')

    function New-FakeLdapConnection {
        [PSCustomObject]@{ Sentinel = 'Phase2Test' }
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
    # one element per octet-string value. Get-ADObjectAclBatch reads
    # $entry.Attributes[<name>][0] and casts to [byte[]], so fixtures must
    # produce the same shape.
    function New-OctetBytes {
        param([Parameter(Mandatory)] [byte[]] $Bytes)
        Write-Output -NoEnumerate ([byte[][]] @(, $Bytes))
    }

    function New-OctetGuid {
        param([Parameter(Mandatory)] [guid] $Guid)
        Write-Output -NoEnumerate ([byte[][]] @(, $Guid.ToByteArray()))
    }

    function New-UserEntry {
        param(
            [Parameter(Mandatory)] [string] $DistinguishedName,
            [Parameter(Mandatory)] [guid] $ObjectGuid,
            [Parameter(Mandatory)] [byte[]] $SdBytes,
            [Parameter()] [string] $StructuralObjectClass = 'user'
        )
        $attrs = @{
            distinguishedName    = @($DistinguishedName)
            objectClass          = @('top', 'person', 'organizationalPerson', 'user')
            objectGUID           = (New-OctetGuid $ObjectGuid)
            nTSecurityDescriptor = (New-OctetBytes $SdBytes)
        }
        if ($StructuralObjectClass) {
            $attrs['structuralObjectClass'] = @($StructuralObjectClass)
        }
        New-LdapEntry -DistinguishedName $DistinguishedName -Attributes $attrs
    }

    $script:DefaultNc = 'DC=lab,DC=local'

    # Helper: collect all batches emitted by Get-ADObjectAclBatch into a List.
    # The @() wrapper is essential — when only one batch is emitted, parenthesised
    # call evaluation collapses the single output to the inner List, which then
    # gets enumerated as PSObjects by foreach. @() forces an Object[] of batches
    # regardless of whether 1 or N batches were emitted.
    function Invoke-CollectBatches {
        param([Parameter(Mandatory)] [hashtable] $Params)
        $collected = [List[object]]::new()
        foreach ($b in @(Get-ADObjectAclBatch @Params)) {
            $collected.Add($b)
        }
        , $collected
    }
}

Describe 'Get-ADObjectAclBatch' {
    BeforeEach {
        $script:Entries = [List[hashtable]]::new()
        Mock Read-LdapEntry {
            foreach ($e in $script:Entries) { $e }
        }
    }

    Context 'empty naming context' {
        It 'emits nothing when the search returns zero entries' {
            $callParams = @{
                Params = @{
                    Connection = New-FakeLdapConnection
                    SearchBase = $script:DefaultNc
                }
            }
            $batches = Invoke-CollectBatches @callParams
            $batches.Count | Should -Be 0
        }
    }

    Context 'batch size handling' {
        It 'emits one batch when entry count is below -BatchSize' {
            $sd = [byte[]] (1, 2, 3, 4)
            for ($i = 0; $i -lt 3; $i++) {
                $script:Entries.Add(
                    (New-UserEntry -DistinguishedName "CN=u$i,$script:DefaultNc" `
                                   -ObjectGuid ([guid]::NewGuid()) `
                                   -SdBytes $sd))
            }

            $callParams = @{
                Params = @{
                    Connection = New-FakeLdapConnection
                    SearchBase = $script:DefaultNc
                    BatchSize  = 5
                }
            }
            $batches = Invoke-CollectBatches @callParams

            $batches.Count    | Should -Be 1
            # Comma-wrap: piping a List[PSObject] to Should unrolls it into
            # individual PSObjects, defeating -BeOfType on the collection.
            , $batches[0]     | Should -BeOfType ([List[PSObject]])
            $batches[0].Count | Should -Be 3
        }

        It 'splits entries into batches of -BatchSize plus a trailing remainder' {
            $sd = [byte[]] (1, 2, 3, 4)
            for ($i = 0; $i -lt 5; $i++) {
                $script:Entries.Add(
                    (New-UserEntry -DistinguishedName "CN=u$i,$script:DefaultNc" `
                                   -ObjectGuid ([guid]::NewGuid()) `
                                   -SdBytes $sd))
            }

            $callParams = @{
                Params = @{
                    Connection = New-FakeLdapConnection
                    SearchBase = $script:DefaultNc
                    BatchSize  = 2
                }
            }
            $batches = Invoke-CollectBatches @callParams

            $batches.Count    | Should -Be 3
            $batches[0].Count | Should -Be 2
            $batches[1].Count | Should -Be 2
            $batches[2].Count | Should -Be 1
        }

        It 'emits exactly two full batches when entry count is a multiple of -BatchSize' {
            $sd = [byte[]] (9, 9)
            for ($i = 0; $i -lt 4; $i++) {
                $script:Entries.Add(
                    (New-UserEntry -DistinguishedName "CN=u$i,$script:DefaultNc" `
                                   -ObjectGuid ([guid]::NewGuid()) `
                                   -SdBytes $sd))
            }

            $callParams = @{
                Params = @{
                    Connection = New-FakeLdapConnection
                    SearchBase = $script:DefaultNc
                    BatchSize  = 2
                }
            }
            $batches = Invoke-CollectBatches @callParams

            $batches.Count    | Should -Be 2
            $batches[0].Count | Should -Be 2
            $batches[1].Count | Should -Be 2
        }
    }

    Context 'attribute extraction' {
        It 'surfaces nTSecurityDescriptor as raw byte[] on the emitted object' {
            $expectedBytes = [byte[]] (10, 20, 30, 40, 50, 60)
            $script:Entries.Add(
                (New-UserEntry -DistinguishedName "CN=u0,$script:DefaultNc" `
                               -ObjectGuid ([guid]::NewGuid()) `
                               -SdBytes $expectedBytes))

            $callParams = @{
                Params = @{
                    Connection = New-FakeLdapConnection
                    SearchBase = $script:DefaultNc
                }
            }
            $batches = Invoke-CollectBatches @callParams
            $obj     = $batches[0][0]

            # Comma-wrap dodges pipeline unrolling of the byte[] into individual
            # bytes; otherwise Should -BeOfType sees [byte] not [byte[]].
            , $obj.NTSecurityDescriptor | Should -BeOfType ([byte[]])
            $obj.NTSecurityDescriptor.Length | Should -Be $expectedBytes.Length
            for ($i = 0; $i -lt $expectedBytes.Length; $i++) {
                $obj.NTSecurityDescriptor[$i] | Should -Be $expectedBytes[$i]
            }
        }

        It 'converts objectGUID bytes into a [guid]' {
            $expectedGuid = [guid] '12345678-1234-1234-1234-123456789abc'
            $script:Entries.Add(
                (New-UserEntry -DistinguishedName "CN=u0,$script:DefaultNc" `
                               -ObjectGuid $expectedGuid `
                               -SdBytes ([byte[]] (1, 2))))

            $callParams = @{
                Params = @{
                    Connection = New-FakeLdapConnection
                    SearchBase = $script:DefaultNc
                }
            }
            $batches = Invoke-CollectBatches @callParams
            $obj     = $batches[0][0]

            $obj.ObjectGUID | Should -BeOfType ([guid])
            $obj.ObjectGUID | Should -Be $expectedGuid
        }

        It 'falls back to the last objectClass value when structuralObjectClass is absent' {
            $script:Entries.Add(
                (New-UserEntry -DistinguishedName "CN=u0,$script:DefaultNc" `
                               -ObjectGuid ([guid]::NewGuid()) `
                               -SdBytes ([byte[]] (1)) `
                               -StructuralObjectClass ''))

            $callParams = @{
                Params = @{
                    Connection = New-FakeLdapConnection
                    SearchBase = $script:DefaultNc
                }
            }
            $batches = Invoke-CollectBatches @callParams
            $obj     = $batches[0][0]

            $obj.StructuralObjectClass | Should -Be 'user'
        }

        It 'prefers structuralObjectClass when present' {
            $entry = New-UserEntry -DistinguishedName "CN=u0,$script:DefaultNc" `
                                   -ObjectGuid ([guid]::NewGuid()) `
                                   -SdBytes ([byte[]] (1)) `
                                   -StructuralObjectClass 'computer'
            $script:Entries.Add($entry)

            $callParams = @{
                Params = @{
                    Connection = New-FakeLdapConnection
                    SearchBase = $script:DefaultNc
                }
            }
            $batches = Invoke-CollectBatches @callParams
            $batches[0][0].StructuralObjectClass | Should -Be 'computer'
        }

        It 'preserves the search-result DistinguishedName' {
            $dn = "CN=Specific,$script:DefaultNc"
            $script:Entries.Add(
                (New-UserEntry -DistinguishedName $dn `
                               -ObjectGuid ([guid]::NewGuid()) `
                               -SdBytes ([byte[]] (1))))

            $callParams = @{
                Params = @{
                    Connection = New-FakeLdapConnection
                    SearchBase = $script:DefaultNc
                }
            }
            $batches = Invoke-CollectBatches @callParams
            $batches[0][0].DistinguishedName | Should -Be $dn
        }
    }

    Context 'LDAP request shape' {
        It 'attaches SecurityDescriptorFlagControl with Owner | Dacl masks' {
            $script:Entries.Add(
                (New-UserEntry -DistinguishedName "CN=u0,$script:DefaultNc" `
                               -ObjectGuid ([guid]::NewGuid()) `
                               -SdBytes ([byte[]] (1))))

            $callParams = @{
                Connection = New-FakeLdapConnection
                SearchBase = $script:DefaultNc
            }
            $null = Invoke-CollectBatches -Params $callParams

            $expectedMasks = [int]([SecurityMasks]::Owner -bor [SecurityMasks]::Dacl)
            $assertParams = @{
                CommandName     = 'Read-LdapEntry'
                Times           = 1
                Exactly         = $true
                ParameterFilter = {
                    $found = $false
                    foreach ($c in $AdditionalControls) {
                        if ($c -is [SecurityDescriptorFlagControl]) {
                            if ([int] $c.SecurityMasks -eq $expectedMasks) {
                                $found = $true
                                break
                            }
                        }
                    }
                    $found
                }
            }
            Should -Invoke @assertParams
        }

        It 'requests objectGUID and nTSecurityDescriptor as binary attributes' {
            $script:Entries.Add(
                (New-UserEntry -DistinguishedName "CN=u0,$script:DefaultNc" `
                               -ObjectGuid ([guid]::NewGuid()) `
                               -SdBytes ([byte[]] (1))))

            $callParams = @{
                Connection = New-FakeLdapConnection
                SearchBase = $script:DefaultNc
            }
            $null = Invoke-CollectBatches -Params $callParams

            $assertParams = @{
                CommandName     = 'Read-LdapEntry'
                Times           = 1
                Exactly         = $true
                ParameterFilter = {
                    ($BinaryAttributes -contains 'objectGUID') -and
                    ($BinaryAttributes -contains 'nTSecurityDescriptor')
                }
            }
            Should -Invoke @assertParams
        }

        It 'searches the requested SearchBase with subtree scope' {
            $script:Entries.Add(
                (New-UserEntry -DistinguishedName "CN=u0,$script:DefaultNc" `
                               -ObjectGuid ([guid]::NewGuid()) `
                               -SdBytes ([byte[]] (1))))

            $callParams = @{
                Connection = New-FakeLdapConnection
                SearchBase = 'CN=Configuration,DC=lab,DC=local'
            }
            $null = Invoke-CollectBatches -Params $callParams

            $assertParams = @{
                CommandName     = 'Read-LdapEntry'
                Times           = 1
                Exactly         = $true
                ParameterFilter = {
                    ($SearchBase -eq 'CN=Configuration,DC=lab,DC=local') -and
                    ($Scope     -eq [SearchScope]::Subtree) -and
                    ($Filter    -eq '(objectClass=*)')
                }
            }
            Should -Invoke @assertParams
        }
    }
}

# Integration test — runs only when a domain is reachable and the caller has
# explicitly opted in with $env:AD_PERM_ANALYZER_INTEGRATION = '1'. Otherwise
# skipped so unit-test runs (CI included) stay deterministic and offline.
Describe 'Get-ADObjectAclBatch (integration)' -Tag 'Integration' {
    BeforeAll {
        $script:RunIntegration = (
            $env:AD_PERM_ANALYZER_INTEGRATION -eq '1' -and
            -not [string]::IsNullOrWhiteSpace($env:USERDNSDOMAIN)
        )
    }

    It 'enumerates at least one object from the current domain root' -Skip:(-not $script:RunIntegration) {
        $connectParams = @{ Domain = $env:USERDNSDOMAIN }
        $connection    = Connect-AdLdap @connectParams
        try {
            $contexts = Get-ADNamingContext -Connection $connection
            $domainNc = ($contexts.Where({ $_.Type -eq 'Domain' }))[0]
            $domainNc | Should -Not -BeNullOrEmpty

            $batchParams = @{
                Connection = $connection
                SearchBase = $domainNc.DistinguishedName
                BatchSize  = 50
                PageSize   = 200
            }
            $first = $null
            foreach ($batch in Get-ADObjectAclBatch @batchParams) {
                $first = $batch
                break
            }
            $first       | Should -Not -BeNullOrEmpty
            $first.Count | Should -BeGreaterThan 0

            $sample = $first[0]
            $sample.DistinguishedName     | Should -Not -BeNullOrEmpty
            , $sample.NTSecurityDescriptor | Should -BeOfType ([byte[]])
            $sample.ObjectGUID             | Should -BeOfType ([guid])
        }
        finally {
            $connection.Dispose()
        }
    }
}
