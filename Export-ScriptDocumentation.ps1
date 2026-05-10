#Requires -Version 7.0

<#
.SYNOPSIS
    Generates markdown documentation from PowerShell script comment-based help.

.DESCRIPTION
    Reads PowerShell scripts and extracts comment-based help via AST parsing.
    Generates individual markdown pages per script plus an index page with a
    summary table and a .pages file for navigation ordering.

    Designed for standalone scripts (not modules) where PlatyPS cannot be used
    because Import-Module is not available. Output format is optimized for
    Zensical (Material theme) rendering with attribute tables for parameters
    instead of PlatyPS YAML blocks.

    Uses the PowerShell AST (Abstract Syntax Tree) to parse help content and
    parameter metadata directly from script files. This is more reliable than
    Get-Help, which can fail on scripts in temporary or non-standard directories.

.PARAMETER ScriptPath
    File or directory of .ps1 files to document. Processes recursively for
    directories. Excludes *.Tests.ps1 and Export-ScriptDocumentation.ps1.

.PARAMETER OutputPath
    Directory for generated markdown files. Defaults to docs/commands/
    relative to the script's directory.

.PARAMETER ProjectName
    Project name used in the index page header.

.PARAMETER ProjectDescription
    Project description used in the index page.

.PARAMETER PassThru
    Returns structured result objects per script processed.

.EXAMPLE
    .\Export-ScriptDocumentation.ps1 -ScriptPath . -ProjectName 'MyProject'
    Generates documentation for all scripts in the current directory.

.EXAMPLE
    .\Export-ScriptDocumentation.ps1 -ScriptPath .\Invoke-Hydrate.ps1 -OutputPath .\docs\commands
    Generates documentation for a single script to a specific output directory.

.EXAMPLE
    .\Export-ScriptDocumentation.ps1 -ScriptPath . -PassThru
    Returns structured result objects showing which scripts were documented.
#>
[CmdletBinding()]
[OutputType([PSCustomObject])]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ScriptPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path -Path $PSScriptRoot -ChildPath 'docs' -AdditionalChildPath 'commands'),

    [Parameter()]
    [string]$ProjectName,

    [Parameter()]
    [string]$ProjectDescription,

    [Parameter()]
    [switch]$PassThru
)

# --- Helper: parse comment-based help block into sections ---
function ConvertFrom-HelpComment {
    param([string]$CommentText)

    # Strip <# and #> delimiters
    $Text = $CommentText -replace '^\s*<#', '' -replace '#>\s*$', ''
    $Lines = $Text -split "`r?`n"

    $Result = @{
        Synopsis    = ''
        Description = ''
        Parameters  = @{}
        Examples    = [System.Collections.Generic.List[hashtable]]::new()
        Inputs      = ''
        Outputs     = ''
        Notes       = ''
    }

    $CurrentSection = $null
    $CurrentParamName = $null
    $Content = [System.Collections.Generic.List[string]]::new()

    foreach ($Line in $Lines) {
        # Remove up to 4 leading spaces (standard help indent)
        $Trimmed = $Line -replace '^\s{1,4}', ''

        if ($Trimmed -match '^\.(SYNOPSIS|DESCRIPTION|PARAMETER|EXAMPLE|INPUTS|OUTPUTS|NOTES)\s*(.*)$') {
            # Save previous section
            if ($CurrentSection) {
                $SectionText = ($Content -join "`n").Trim()
                switch ($CurrentSection) {
                    'SYNOPSIS'    { $Result.Synopsis = $SectionText }
                    'DESCRIPTION' { $Result.Description = $SectionText }
                    'PARAMETER'   { if ($CurrentParamName) { $Result.Parameters[$CurrentParamName] = $SectionText } }
                    'EXAMPLE'     { $Result.Examples.Add(@{ Text = $SectionText }) }
                    'INPUTS'      { $Result.Inputs = $SectionText }
                    'OUTPUTS'     { $Result.Outputs = $SectionText }
                    'NOTES'       { $Result.Notes = $SectionText }
                }
            }

            $CurrentSection = $Matches[1]
            $CurrentParamName = if ($CurrentSection -eq 'PARAMETER') { $Matches[2].Trim() } else { $null }
            $Content = [System.Collections.Generic.List[string]]::new()
        } else {
            $Content.Add($Trimmed)
        }
    }

    # Save last section
    if ($CurrentSection) {
        $SectionText = ($Content -join "`n").Trim()
        switch ($CurrentSection) {
            'SYNOPSIS'    { $Result.Synopsis = $SectionText }
            'DESCRIPTION' { $Result.Description = $SectionText }
            'PARAMETER'   { if ($CurrentParamName) { $Result.Parameters[$CurrentParamName] = $SectionText } }
            'EXAMPLE'     { $Result.Examples.Add(@{ Text = $SectionText }) }
            'INPUTS'      { $Result.Inputs = $SectionText }
            'OUTPUTS'     { $Result.Outputs = $SectionText }
            'NOTES'       { $Result.Notes = $SectionText }
        }
    }

    $Result
}

# --- Helper: extract parameter metadata from AST param block ---
function Get-ParamBlockInfo {
    param([System.Management.Automation.Language.ParamBlockAst]$ParamBlock)

    $Params = [System.Collections.Generic.List[PSCustomObject]]::new()
    if (-not $ParamBlock) { $Params; return }

    # Detect SupportsShouldProcess from CmdletBinding attribute
    $CmdBindingAttrs = $ParamBlock.Attributes.Where({ $_.TypeName.Name -eq 'CmdletBinding' })
    $HasShouldProcess = $false
    if ($CmdBindingAttrs.Count -gt 0) {
        $SpArgs = $CmdBindingAttrs[0].NamedArguments.Where({ $_.ArgumentName -eq 'SupportsShouldProcess' })
        $HasShouldProcess = $SpArgs.Count -gt 0
    }

    foreach ($p in $ParamBlock.Parameters) {
        $Name = $p.Name.VariablePath.UserPath
        $TypeName = $p.StaticType.Name
        $Default = if ($p.DefaultValue) { $p.DefaultValue.Extent.Text } else { '' }
        $IsMandatory = $false
        $Position = 'Named'

        foreach ($attr in $p.Attributes) {
            if ($attr.TypeName.Name -eq 'Parameter') {
                foreach ($arg in $attr.NamedArguments) {
                    if ($arg.ArgumentName -eq 'Mandatory') { $IsMandatory = $true }
                    if ($arg.ArgumentName -eq 'Position') { $Position = $arg.Argument.Extent.Text }
                }
            }
        }

        $Params.Add([PSCustomObject]@{
            Name       = $Name
            TypeName   = $TypeName
            Required   = $IsMandatory
            Default    = $Default
            Position   = $Position
            IsSwitch   = $TypeName -eq 'SwitchParameter'
        })
    }

    @{
        Parameters       = $Params
        ShouldProcess    = $HasShouldProcess
    }
}

# --- Resolve script files ---
$ResolvedPath = Resolve-Path -Path $ScriptPath -ErrorAction Stop

$ScriptFiles = if (Test-Path -Path $ResolvedPath -PathType Container) {
    $AllFiles = Get-ChildItem -Path $ResolvedPath -Filter '*.ps1' -Recurse
    $AllFiles.Where({
        $_.Name -notlike '*.Tests.ps1' -and
        $_.Name -ne 'Export-ScriptDocumentation.ps1'
    })
} else {
    @(Get-Item -Path $ResolvedPath)
}

if ($ScriptFiles.Count -eq 0) {
    Write-Warning "No .ps1 files found at '$ScriptPath'"
    return
}

# --- Ensure output directory ---
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()
$IndexEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

foreach ($File in $ScriptFiles) {
    $ScriptName = [System.IO.Path]::GetFileNameWithoutExtension($File.Name)
    $OutputFile = Join-Path -Path $OutputPath -ChildPath "$ScriptName.md"

    Write-Verbose "Processing $($File.Name)"

    # --- Parse script with AST ---
    $Tokens = $null
    $ParseErrors = $null
    $Ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $File.FullName, [ref]$Tokens, [ref]$ParseErrors
    )

    # Find comment block containing .SYNOPSIS
    $HelpTokens = $Tokens.Where({
        $_.Kind -eq 'Comment' -and $_.Text -match '\.SYNOPSIS'
    }, 'First')

    if ($HelpTokens.Count -eq 0) {
        Write-Warning "No comment-based help found for '$($File.Name)' — skipping"
        $Results.Add([PSCustomObject]@{
            ScriptName = $ScriptName
            ScriptPath = $File.FullName
            OutputFile = $OutputFile
            Generated  = $false
            Sections   = @()
        })
        continue
    }

    # Parse help sections from comment block
    $HelpInfo = ConvertFrom-HelpComment -CommentText $HelpTokens[0].Text

    if (-not $HelpInfo.Synopsis) {
        Write-Warning "No meaningful help found for '$($File.Name)' — skipping"
        $Results.Add([PSCustomObject]@{
            ScriptName = $ScriptName
            ScriptPath = $File.FullName
            OutputFile = $OutputFile
            Generated  = $false
            Sections   = @()
        })
        continue
    }

    # Get parameter metadata from AST
    $ParamInfo = Get-ParamBlockInfo -ParamBlock $Ast.ParamBlock
    $ScriptParams = $ParamInfo.Parameters
    $HasShouldProcess = $ParamInfo.ShouldProcess

    $Synopsis = $HelpInfo.Synopsis
    $Sections = [System.Collections.Generic.List[string]]::new()
    $Md = [System.Text.StringBuilder]::new()

    # --- H1: Script name ---
    [void]$Md.AppendLine("# $ScriptName")
    [void]$Md.AppendLine()

    # --- Synopsis ---
    $Sections.Add('Synopsis')
    [void]$Md.AppendLine('## Synopsis')
    [void]$Md.AppendLine()
    [void]$Md.AppendLine($Synopsis)
    [void]$Md.AppendLine()

    # --- Description ---
    if ($HelpInfo.Description) {
        $Sections.Add('Description')
        [void]$Md.AppendLine('## Description')
        [void]$Md.AppendLine()
        [void]$Md.AppendLine($HelpInfo.Description)
        [void]$Md.AppendLine()
    }

    # --- Syntax ---
    if ($ScriptParams.Count -gt 0 -or $HasShouldProcess) {
        $Sections.Add('Syntax')
        [void]$Md.AppendLine('## Syntax')
        [void]$Md.AppendLine()
        [void]$Md.AppendLine('```')

        $SyntaxParts = [System.Collections.Generic.List[string]]::new()
        $SyntaxParts.Add(".\$($File.Name)")

        foreach ($Param in $ScriptParams) {
            $DisplayType = $Param.TypeName.ToLower()
            if ($Param.IsSwitch) {
                if ($Param.Required) {
                    $SyntaxParts.Add("-$($Param.Name)")
                } else {
                    $SyntaxParts.Add("[-$($Param.Name)]")
                }
            } elseif ($Param.Required) {
                $SyntaxParts.Add("-$($Param.Name) <$DisplayType>")
            } else {
                $SyntaxParts.Add("[-$($Param.Name) <$DisplayType>]")
            }
        }

        if ($HasShouldProcess) {
            $SyntaxParts.Add('[-WhatIf]')
            $SyntaxParts.Add('[-Confirm]')
        }
        $SyntaxParts.Add('[<CommonParameters>]')

        # Join and wrap long lines
        $SyntaxLine = $SyntaxParts -join ' '
        if ($SyntaxLine.Length -gt 100) {
            $WrapLines = [System.Collections.Generic.List[string]]::new()
            $CurrentLine = $SyntaxParts[0]
            for ($i = 1; $i -lt $SyntaxParts.Count; $i++) {
                $TestLine = "$CurrentLine $($SyntaxParts[$i])"
                if ($TestLine.Length -gt 100 -and $CurrentLine -ne $SyntaxParts[0]) {
                    $WrapLines.Add($CurrentLine)
                    $CurrentLine = " $($SyntaxParts[$i])"
                } else {
                    $CurrentLine = $TestLine
                }
            }
            $WrapLines.Add($CurrentLine)
            [void]$Md.AppendLine($WrapLines -join "`n")
        } else {
            [void]$Md.AppendLine($SyntaxLine)
        }

        [void]$Md.AppendLine('```')
        [void]$Md.AppendLine()
    }

    # --- Parameters ---
    if ($ScriptParams.Count -gt 0) {
        $Sections.Add('Parameters')
        [void]$Md.AppendLine('## Parameters')
        [void]$Md.AppendLine()

        foreach ($Param in $ScriptParams) {
            [void]$Md.AppendLine("### -$($Param.Name)")
            [void]$Md.AppendLine()

            # Parameter description from help comment
            $ParamDesc = $HelpInfo.Parameters[$Param.Name]
            if ($ParamDesc) {
                [void]$Md.AppendLine($ParamDesc)
                [void]$Md.AppendLine()
            }

            $Required = if ($Param.Required) { 'True' } else { 'False' }
            $DefaultVal = if ($Param.Default -and -not $Param.IsSwitch) { $Param.Default } else { '—' }
            $Position = $Param.Position

            [void]$Md.AppendLine('| Attribute | Value |')
            [void]$Md.AppendLine('|-----------|-------|')
            [void]$Md.AppendLine("| Type | $($Param.TypeName) |")
            [void]$Md.AppendLine("| Required | $Required |")
            [void]$Md.AppendLine("| Default | $DefaultVal |")
            [void]$Md.AppendLine("| Position | $Position |")
            [void]$Md.AppendLine()
        }

        # CommonParameters section
        [void]$Md.AppendLine('### CommonParameters')
        [void]$Md.AppendLine()
        if ($HasShouldProcess) {
            [void]$Md.AppendLine(
                'This script supports the common parameters: -Debug, -ErrorAction, ' +
                '-ErrorVariable, -InformationAction, -InformationVariable, -OutBuffer, ' +
                '-OutVariable, -PipelineVariable, -ProgressAction, -Verbose, -WarningAction, ' +
                '-WarningVariable, -WhatIf, and -Confirm. For more information, see ' +
                '[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).'
            )
        } else {
            [void]$Md.AppendLine(
                'This script supports the common parameters: -Debug, -ErrorAction, ' +
                '-ErrorVariable, -InformationAction, -InformationVariable, -OutBuffer, ' +
                '-OutVariable, -PipelineVariable, -ProgressAction, -Verbose, -WarningAction, ' +
                'and -WarningVariable. For more information, see ' +
                '[about_CommonParameters](https://go.microsoft.com/fwlink/?LinkID=113216).'
            )
        }
        [void]$Md.AppendLine()
    }

    # --- Examples ---
    if ($HelpInfo.Examples.Count -gt 0) {
        $Sections.Add('Examples')
        [void]$Md.AppendLine('## Examples')
        [void]$Md.AppendLine()

        $ExNum = 0
        foreach ($Example in $HelpInfo.Examples) {
            $ExNum++
            $ExText = $Example.Text

            # Split example text into code and description.
            # First contiguous block of lines is code; rest is description.
            # Multi-line splats (@{ ... }), pipe/backtick continuations, and
            # parameter lines all keep accumulating into the command block.
            # Once a multi-line block has started, the blank line that follows
            # the closing brace is the divider, not the next non-prose-shaped
            # line — so we stay in command mode until that blank.
            $ExLines = $ExText -split "`n"
            $CommandLines = [System.Collections.Generic.List[string]]::new()
            $DescLines = [System.Collections.Generic.List[string]]::new()
            $StillInCommand = $true
            $BraceDepth = 0
            $EverNested = $false

            foreach ($ExLine in $ExLines) {
                $LineTrimmed = $ExLine.Trim()
                if (-not $LineTrimmed) {
                    if ($BraceDepth -le 0) { $StillInCommand = $false }
                    continue
                }
                if ($StillInCommand) {
                    $InCommand = ($CommandLines.Count -eq 0) -or
                                 ($BraceDepth -gt 0) -or
                                 $EverNested -or
                                 $CommandLines[-1].EndsWith('`') -or
                                 $CommandLines[-1].EndsWith('|') -or
                                 $LineTrimmed.StartsWith('-') -or
                                 $LineTrimmed.StartsWith('|')
                    if ($InCommand) {
                        $CommandLines.Add($LineTrimmed)
                        # Naive brace-depth tracking — sufficient for typical
                        # help examples; would over/undercount for unbalanced
                        # braces inside string literals.
                        $Opens = ($LineTrimmed.ToCharArray().Where({ $_ -in '{','(','[' })).Count
                        $Closes = ($LineTrimmed.ToCharArray().Where({ $_ -in '}',')',']' })).Count
                        $BraceDepth += ($Opens - $Closes)
                        if ($BraceDepth -gt 0) { $EverNested = $true }
                    } else {
                        $StillInCommand = $false
                        $DescLines.Add($LineTrimmed)
                    }
                } else {
                    $DescLines.Add($LineTrimmed)
                }
            }

            $Code = $CommandLines -join "`n"
            $Desc = ($DescLines -join "`n").Trim()

            # Build example title from first line of description
            $ExTitle = "Example $ExNum"
            if ($Desc) {
                $FirstLine = ($Desc -split "`n", 2)[0].Trim().TrimEnd('.')
                if ($FirstLine.Length -gt 80) {
                    $FirstLine = $FirstLine.Substring(0, 77) + '...'
                }
                if ($FirstLine) {
                    $ExTitle = "Example ${ExNum}: $FirstLine"
                }
            }

            [void]$Md.AppendLine("### $ExTitle")
            [void]$Md.AppendLine()

            if ($Code) {
                [void]$Md.AppendLine('```powershell')
                [void]$Md.AppendLine($Code)
                [void]$Md.AppendLine('```')
                [void]$Md.AppendLine()
            }

            if ($Desc) {
                [void]$Md.AppendLine($Desc)
                [void]$Md.AppendLine()
            }
        }
    }

    # --- Inputs ---
    $Sections.Add('Inputs')
    [void]$Md.AppendLine('## Inputs')
    [void]$Md.AppendLine()
    [void]$Md.AppendLine($(if ($HelpInfo.Inputs) { $HelpInfo.Inputs } else { 'None.' }))
    [void]$Md.AppendLine()

    # --- Outputs ---
    $Sections.Add('Outputs')
    [void]$Md.AppendLine('## Outputs')
    [void]$Md.AppendLine()
    if ($HelpInfo.Outputs) {
        [void]$Md.AppendLine($HelpInfo.Outputs)
    } else {
        [void]$Md.AppendLine('None.')
    }
    [void]$Md.AppendLine()

    # --- Notes ---
    if ($HelpInfo.Notes) {
        $Sections.Add('Notes')
        [void]$Md.AppendLine('## Notes')
        [void]$Md.AppendLine()
        [void]$Md.AppendLine($HelpInfo.Notes)
        [void]$Md.AppendLine()
    }

    # --- Write file ---
    $Content = $Md.ToString().TrimEnd() + "`n"
    [System.IO.File]::WriteAllText($OutputFile, $Content, $Utf8NoBom)

    Write-Verbose "Generated $OutputFile"

    $IndexEntries.Add([PSCustomObject]@{
        ScriptName = $ScriptName
        Synopsis   = $Synopsis
        FileName   = "$ScriptName.md"
    })

    $Results.Add([PSCustomObject]@{
        ScriptName = $ScriptName
        ScriptPath = $File.FullName
        OutputFile = $OutputFile
        Generated  = $true
        Sections   = $Sections.ToArray()
    })
}

# --- Generate index page ---
$IndexMd = [System.Text.StringBuilder]::new()

if ($ProjectName) {
    [void]$IndexMd.AppendLine("# $ProjectName")
} else {
    [void]$IndexMd.AppendLine('# Command Reference')
}
[void]$IndexMd.AppendLine()

if ($ProjectDescription) {
    [void]$IndexMd.AppendLine($ProjectDescription)
    [void]$IndexMd.AppendLine()
}

[void]$IndexMd.AppendLine('## Commands')
[void]$IndexMd.AppendLine()
[void]$IndexMd.AppendLine('| Script | Description |')
[void]$IndexMd.AppendLine('|--------|-------------|')

foreach ($Entry in $IndexEntries) {
    [void]$IndexMd.AppendLine("| [$($Entry.ScriptName)]($($Entry.FileName)) | $($Entry.Synopsis) |")
}
[void]$IndexMd.AppendLine()

$IndexPath = Join-Path -Path $OutputPath -ChildPath 'index.md'
$IndexContent = $IndexMd.ToString().TrimEnd() + "`n"
[System.IO.File]::WriteAllText($IndexPath, $IndexContent, $Utf8NoBom)

Write-Verbose "Generated index at $IndexPath"

# --- Output ---
if ($PassThru) {
    $Results.ToArray()
}
