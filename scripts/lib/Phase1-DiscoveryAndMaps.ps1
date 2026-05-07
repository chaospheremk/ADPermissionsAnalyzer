#Requires -Version 7.0
using namespace System.Collections.Generic
using namespace System.DirectoryServices.Protocols

<#
.SYNOPSIS
    Phase 1 helpers for AD Permissions Analyzer: LDAP bind, naming-context discovery,
    and GUID/SID map construction.

.DESCRIPTION
    Implements §5 Phase 1 and §8 GUID Map Construction Details from
    docs/AD-Permissions-Analyzer-Plan.md. Dot-sourced by the entry-point script
    Invoke-ADPermissionAnalysis.ps1 and exercised in isolation by the matching
    Pester suite under Tests/.

    The IO boundary is Invoke-PagedLdapSearch; the map builders depend on it and
    are mocked at that boundary for unit tests.
#>

function Connect-AdLdap {
    <#
    .SYNOPSIS
        Open and bind an LdapConnection to a domain controller via Negotiate auth.

    .DESCRIPTION
        Resolves the LDAP target in this order: explicit -Server, then -Domain,
        then $env:USERDNSDOMAIN. Connects on port 389 with Kerberos (NTLM
        fallback inside Negotiate). LDAPS and Basic auth are out of scope per
        plan §15. Throws on bind failure (unrecoverable per §14).

    .PARAMETER Server
        Specific DC fully-qualified DNS name. Wins over Domain when supplied.

    .PARAMETER Domain
        Domain DNS name; the OS DC locator picks a DC.

    .PARAMETER Credential
        Optional alternate credential. Default: current process identity.
    #>
    [CmdletBinding()]
    [OutputType([LdapConnection])]
    param(
        [Parameter()]
        [string] $Server,

        [Parameter()]
        [string] $Domain,

        [Parameter()]
        [PSCredential] $Credential
    )

    $target = if     ($Server) { $Server }
              elseif ($Domain) { $Domain }
              else             { $env:USERDNSDOMAIN }

    if (-not $target) {
        throw 'No -Server or -Domain provided and $env:USERDNSDOMAIN is empty.'
    }

    $identifier = [LdapDirectoryIdentifier]::new($target, 389, $false, $true)
    $connection = [LdapConnection]::new($identifier)
    $connection.AuthType = [AuthType]::Negotiate
    if ($Credential) {
        $connection.Credential = $Credential.GetNetworkCredential()
    }
    $connection.Bind()

    , $connection
}

function Invoke-PagedLdapSearch {
    <#
    .SYNOPSIS
        Run a paged subtree LDAP search and return all entries normalised to
        plain hashtables.

    .DESCRIPTION
        Wraps SearchRequest + PageResultRequestControl. Each returned entry is a
        hashtable with keys DistinguishedName (string) and Attributes
        (hashtable name -> values). Values for attributes named in
        -BinaryAttributes are extracted as byte[][]; all others are extracted
        as string[]. This is the single IO boundary for Phase 1, so unit tests
        mock it to feed synthetic entries to the map builders.

    .PARAMETER Connection
        Already-bound LdapConnection. Untyped at the parameter level so unit
        tests can mock this function without instantiating a real
        [LdapConnection] (whose constructor binds eagerly and fails offline).
        Production callers always pass a real LdapConnection.

    .PARAMETER SearchBase
        Base DN to search from.

    .PARAMETER Filter
        LDAP search filter.

    .PARAMETER Attributes
        Attribute names to retrieve.

    .PARAMETER BinaryAttributes
        Subset of -Attributes that should be returned as byte[][] rather than
        string[]. Used for octet-string attributes (schemaIDGUID,
        attributeSecurityGUID, etc).

    .PARAMETER PageSize
        LDAP page size. Default 1000 (the AD server-side cap).

    .PARAMETER Scope
        Search scope. Default Subtree.
    #>
    [CmdletBinding()]
    [OutputType([List[hashtable]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Connection,

        [Parameter(Mandatory)]
        [string] $SearchBase,

        [Parameter(Mandatory)]
        [string] $Filter,

        [Parameter(Mandatory)]
        [string[]] $Attributes,

        [Parameter()]
        [string[]] $BinaryAttributes = @(),

        [Parameter()]
        [ValidateRange(1, 5000)]
        [int] $PageSize = 1000,

        [Parameter()]
        [SearchScope] $Scope = [SearchScope]::Subtree
    )

    $results     = [List[hashtable]]::new()
    $request     = [SearchRequest]::new($SearchBase, $Filter, $Scope, $Attributes)
    $pageControl = [PageResultRequestControl]::new($PageSize)
    [void] $request.Controls.Add($pageControl)

    $binarySet = [HashSet[string]]::new(
        [string[]] $BinaryAttributes,
        [System.StringComparer]::OrdinalIgnoreCase)

    while ($true) {
        $response = [SearchResponse] $Connection.SendRequest($request)

        foreach ($entry in $response.Entries) {
            $attrs = @{}
            foreach ($name in $entry.Attributes.AttributeNames) {
                $attr = $entry.Attributes[$name]
                $attrs[$name] = if ($binarySet.Contains($name)) {
                    $attr.GetValues([byte[]])
                }
                else {
                    $attr.GetValues([string])
                }
            }
            $results.Add(@{
                DistinguishedName = $entry.DistinguishedName
                Attributes        = $attrs
            })
        }

        $pageResp = $null
        foreach ($control in $response.Controls) {
            if ($control -is [PageResultResponseControl]) {
                $pageResp = $control
                break
            }
        }
        if ($null -eq $pageResp -or $pageResp.Cookie.Length -eq 0) {
            break
        }
        $pageControl.Cookie = $pageResp.Cookie
    }

    , $results
}

function Get-NamingContextType {
    <#
    .SYNOPSIS
        Categorise an NC DN as Domain, Configuration, Schema, DNS, or Other.

    .DESCRIPTION
        Pure function so the categorisation rule is testable without a live
        LdapConnection. Used by Get-ADNamingContext.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $NamingContext,

        [Parameter(Mandatory)]
        [string] $DefaultNc,

        [Parameter(Mandatory)]
        [string] $ConfigurationNc,

        [Parameter(Mandatory)]
        [string] $SchemaNc
    )

    if     ($NamingContext -ieq $DefaultNc)       { 'Domain' }
    elseif ($NamingContext -ieq $ConfigurationNc) { 'Configuration' }
    elseif ($NamingContext -ieq $SchemaNc)        { 'Schema' }
    elseif ($NamingContext -like 'DC=DomainDnsZones,*' -or
            $NamingContext -like 'DC=ForestDnsZones,*') { 'DNS' }
    else                                          { 'Other' }
}

function Get-ADNamingContext {
    <#
    .SYNOPSIS
        Enumerate the target DC's naming contexts via a RootDSE base search.

    .DESCRIPTION
        Returns a List[PSObject], one entry per NC, with DistinguishedName and
        Type (Domain/Configuration/Schema/DNS/Other) populated from the
        RootDSE attributes namingContexts, defaultNamingContext,
        configurationNamingContext, and schemaNamingContext. Throws if the
        RootDSE search returns nothing (unrecoverable per plan §14).

    .PARAMETER Connection
        Already-bound LdapConnection (see Connect-AdLdap).
    #>
    [CmdletBinding()]
    [OutputType([List[PSObject]])]
    param(
        [Parameter(Mandatory)]
        [LdapConnection] $Connection
    )

    $rootAttrs = @(
        'namingContexts'
        'defaultNamingContext'
        'configurationNamingContext'
        'schemaNamingContext'
        'rootDomainNamingContext'
    )
    $request  = [SearchRequest]::new('', '(objectClass=*)', [SearchScope]::Base, $rootAttrs)
    $response = [SearchResponse] $Connection.SendRequest($request)
    if ($response.Entries.Count -eq 0) {
        throw 'RootDSE search returned no entries.'
    }

    $rootDse        = $response.Entries[0]
    $defaultNc      = $rootDse.Attributes['defaultNamingContext'][0]
    $configurationNc = $rootDse.Attributes['configurationNamingContext'][0]
    $schemaNc       = $rootDse.Attributes['schemaNamingContext'][0]
    $allNcs         = $rootDse.Attributes['namingContexts'].GetValues([string])

    $contexts = [List[PSObject]]::new()
    foreach ($nc in $allNcs) {
        $typeParams = @{
            NamingContext   = $nc
            DefaultNc       = $defaultNc
            ConfigurationNc = $configurationNc
            SchemaNc        = $schemaNc
        }
        $type = Get-NamingContextType @typeParams
        $contexts.Add([PSCustomObject]@{
            DistinguishedName = $nc
            Type              = $type
        })
    }

    , $contexts
}

function New-ADExtendedRightsMap {
    <#
    .SYNOPSIS
        Build the rightsGuid -> control-access-right map (extended rights,
        validated writes, and property sets) from CN=Extended-Rights.

    .DESCRIPTION
        See plan §5 and §8. Each value carries DisplayName, CommonName,
        AppliesTo (schema GUIDs the right binds to), ValidAccesses (raw mask),
        and RightKind ('ExtendedRight' for 0x100, 'ValidatedWrite' for 0x08,
        'PropertySet' for 0x30). Entries with unknown masks are recorded with
        RightKind = 'Unknown' so forensic output never silently drops them.

    .PARAMETER Connection
        Bound LdapConnection.

    .PARAMETER ConfigurationNamingContext
        DN of the Configuration NC (the Extended-Rights container is below it).

    .PARAMETER PageSize
        LDAP page size. Default 1000.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure constructor: builds and returns an in-memory map; no external state mutated.')]
    [CmdletBinding()]
    [OutputType([Dictionary[guid, PSObject]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Connection,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ConfigurationNamingContext,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int] $PageSize = 1000
    )

    $searchParams = @{
        Connection = $Connection
        SearchBase = "CN=Extended-Rights,$ConfigurationNamingContext"
        Filter     = '(objectClass=controlAccessRight)'
        Attributes = @('cn', 'displayName', 'rightsGuid', 'appliesTo', 'validAccesses')
        PageSize   = $PageSize
    }
    $entries = Invoke-PagedLdapSearch @searchParams

    $map = [Dictionary[guid, PSObject]]::new()
    foreach ($entry in $entries) {
        $rightsGuidValues = $entry.Attributes['rightsGuid']
        if (-not $rightsGuidValues) { continue }
        $rightsGuid = [guid] $rightsGuidValues[0]

        $validAccessesRaw = $entry.Attributes['validAccesses']
        $validAccesses    = if ($validAccessesRaw) { [int] $validAccessesRaw[0] } else { 0 }

        $rightKind = switch ($validAccesses) {
            256     { 'ExtendedRight' }
            8       { 'ValidatedWrite' }
            48      { 'PropertySet' }
            default { 'Unknown' }
        }

        $cn          = if ($entry.Attributes['cn'])          { $entry.Attributes['cn'][0] }          else { '' }
        $displayName = if ($entry.Attributes['displayName']) { $entry.Attributes['displayName'][0] } else { $cn }
        $appliesTo   = if ($entry.Attributes['appliesTo'])   { @($entry.Attributes['appliesTo']) }   else { @() }

        $map[$rightsGuid] = [PSCustomObject]@{
            DisplayName   = $displayName
            CommonName    = $cn
            AppliesTo     = $appliesTo
            ValidAccesses = $validAccesses
            RightKind     = $rightKind
        }
    }

    , $map
}

function New-ADSchemaGuidMap {
    <#
    .SYNOPSIS
        Build the schemaIDGUID -> attribute/class map from the Schema NC.

    .DESCRIPTION
        See plan §5 and §8. Each value carries LdapDisplayName and
        ObjectCategory ('attributeSchema' or 'classSchema'). Property sets are
        not in this map; they live in the Extended-Rights map keyed by
        rightsGuid.

    .PARAMETER Connection
        Bound LdapConnection.

    .PARAMETER SchemaNamingContext
        DN of the Schema NC.

    .PARAMETER PageSize
        LDAP page size. Default 1000.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure constructor: builds and returns an in-memory map; no external state mutated.')]
    [CmdletBinding()]
    [OutputType([Dictionary[guid, PSObject]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Connection,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $SchemaNamingContext,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int] $PageSize = 1000
    )

    $searchParams = @{
        Connection       = $Connection
        SearchBase       = $SchemaNamingContext
        Filter           = '(|(objectClass=attributeSchema)(objectClass=classSchema))'
        Attributes       = @('lDAPDisplayName', 'schemaIDGUID', 'objectClass')
        BinaryAttributes = @('schemaIDGUID')
        PageSize         = $PageSize
    }
    $entries = Invoke-PagedLdapSearch @searchParams

    $map = [Dictionary[guid, PSObject]]::new()
    foreach ($entry in $entries) {
        $guidValues = $entry.Attributes['schemaIDGUID']
        if (-not $guidValues) { continue }
        $schemaGuid = [guid]::new([byte[]] $guidValues[0])

        $ldapName     = if ($entry.Attributes['lDAPDisplayName']) { $entry.Attributes['lDAPDisplayName'][0] } else { '' }
        $objectClasses = if ($entry.Attributes['objectClass'])    { @($entry.Attributes['objectClass']) }    else { @() }

        $category = if     ($objectClasses -contains 'classSchema')     { 'classSchema' }
                    elseif ($objectClasses -contains 'attributeSchema') { 'attributeSchema' }
                    else                                                { 'unknown' }

        $map[$schemaGuid] = [PSCustomObject]@{
            LdapDisplayName = $ldapName
            ObjectCategory  = $category
        }
    }

    , $map
}

function New-PropertySetMembersMap {
    <#
    .SYNOPSIS
        Build the property-set rightsGuid -> member-attribute-name list from
        the Schema NC.

    .DESCRIPTION
        See plan §5 and §8. Reverse-indexes attributeSchema objects whose
        attributeSecurityGUID is non-null. The attributeSecurityGUID equals
        the property set's rightsGuid (an extended-right GUID), not its
        schemaIDGUID. Used by Phase 3 ACE decoding to expand a property-set
        ACE to its constituent attribute names.

    .PARAMETER Connection
        Bound LdapConnection.

    .PARAMETER SchemaNamingContext
        DN of the Schema NC.

    .PARAMETER PageSize
        LDAP page size. Default 1000.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure constructor: builds and returns an in-memory map; no external state mutated.')]
    [CmdletBinding()]
    [OutputType([Dictionary[guid, List[string]]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Connection,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $SchemaNamingContext,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int] $PageSize = 1000
    )

    $searchParams = @{
        Connection       = $Connection
        SearchBase       = $SchemaNamingContext
        Filter           = '(&(objectClass=attributeSchema)(attributeSecurityGUID=*))'
        Attributes       = @('lDAPDisplayName', 'attributeSecurityGUID')
        BinaryAttributes = @('attributeSecurityGUID')
        PageSize         = $PageSize
    }
    $entries = Invoke-PagedLdapSearch @searchParams

    $map = [Dictionary[guid, List[string]]]::new()
    foreach ($entry in $entries) {
        $guidValues = $entry.Attributes['attributeSecurityGUID']
        if (-not $guidValues) { continue }
        $setGuid = [guid]::new([byte[]] $guidValues[0])

        $ldapValues = $entry.Attributes['lDAPDisplayName']
        if (-not $ldapValues) { continue }
        $ldapName = $ldapValues[0]

        if (-not $map.ContainsKey($setGuid)) {
            $map[$setGuid] = [List[string]]::new()
        }
        $map[$setGuid].Add($ldapName)
    }

    , $map
}

function New-WellKnownSidMap {
    <#
    .SYNOPSIS
        Static SID -> friendly-name map for cross-domain well-known SIDs.

    .DESCRIPTION
        Pre-populates well-known SIDs that NTAccount.Translate() may not
        resolve reliably across all environments, plus the universal
        principals listed in plan §10 (Everyone, CREATOR OWNER, SELF, etc.).
        BUILTIN aliases (S-1-5-32-*) are intentionally excluded — they
        translate via NTAccount and have no AD-wide membership semantics
        relevant to this analyser. Keys use ordinal-ignore-case comparison so
        callers don't need to normalise SID strings.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure constructor: builds and returns an in-memory map; no external state mutated.')]
    [CmdletBinding()]
    [OutputType([Dictionary[string, string]])]
    param()

    $map = [Dictionary[string, string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    $entries = [ordered]@{
        'S-1-0-0'  = 'NULL SID'
        'S-1-1-0'  = 'Everyone'
        'S-1-2-0'  = 'LOCAL'
        'S-1-2-1'  = 'CONSOLE LOGON'
        'S-1-3-0'  = 'CREATOR OWNER'
        'S-1-3-1'  = 'CREATOR GROUP'
        'S-1-3-2'  = 'CREATOR OWNER SERVER'
        'S-1-3-3'  = 'CREATOR GROUP SERVER'
        'S-1-3-4'  = 'OWNER RIGHTS'
        'S-1-5-1'  = 'DIALUP'
        'S-1-5-2'  = 'NETWORK'
        'S-1-5-3'  = 'BATCH'
        'S-1-5-4'  = 'INTERACTIVE'
        'S-1-5-6'  = 'SERVICE'
        'S-1-5-7'  = 'ANONYMOUS LOGON'
        'S-1-5-8'  = 'PROXY'
        'S-1-5-9'  = 'ENTERPRISE DOMAIN CONTROLLERS'
        'S-1-5-10' = 'SELF'
        'S-1-5-11' = 'Authenticated Users'
        'S-1-5-12' = 'RESTRICTED CODE'
        'S-1-5-13' = 'TERMINAL SERVER USER'
        'S-1-5-14' = 'REMOTE INTERACTIVE LOGON'
        'S-1-5-15' = 'THIS ORGANIZATION'
        'S-1-5-17' = 'IUSR'
        'S-1-5-18' = 'SYSTEM'
        'S-1-5-19' = 'LOCAL SERVICE'
        'S-1-5-20' = 'NETWORK SERVICE'
    }
    foreach ($kvp in $entries.GetEnumerator()) {
        $map[$kvp.Key] = $kvp.Value
    }

    , $map
}
