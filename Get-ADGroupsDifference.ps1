Function Get-ADGroupsDifference {

<#
    .SYNOPSIS
    PowerShell function intended to compare group membership for two Active Directory users.

    .DESCRIPTION
    Using this function you can compare groups membership for two users Active Directory users.
    The first is reference user, the second is compared with it and as the result groups different for both users will be displayed.

    .PARAMETER ReferenceUser
    Active Directory user object used as source for comparison - reference user

    The acceptable values for this parameter are:
    -- A Distinguished Name
    -- A GUID (objectGUID)
    -- A Security Identifier (objectSid)
    -- A SAM Account Name (sAMAccountName)

    .PARAMETER User
    Active Directory user object for which group membership comparison will be performed

    The acceptable values for this parameter are:
    -- A Distinguished Name
    -- A GUID (objectGUID)
    -- A Security Identifier (objectSid)
    -- A SAM Account Name (sAMAccountName)

    .PARAMETER DomainName
    Active Directory domain name - NETBIOS or FQDN - if not given than current domain for logged user is used.

    .PARAMETER IncludeEqual
    If selected also groups for what both users belong will be returned.

    .EXAMPLE
    Get-ADGroupsDifference -ReferenceUser XXXX -User YYYY

    ReferenceUser          : XXXX
    User                   : YYYY
    Group                  : GroupA
    SideIndicator          : 1
    SideIndicatorName      : Only User

    ReferenceUser          : XXXX
    User                   : YYYY
    Group                  : GroupB
    SideIndicator          : -1
    SideIndicatorName      : Only ReferenceUser

    ReferenceUser          : XXXX
    User                   : YYYY
    Group                  : Group-007-License
    SideIndicator          : -1
    SideIndicatorName      : Only ReferenceUser

    .EXAMPLE
    Get-ADGroupsDifference -ReferenceUser XXXX -User YYYY | Where { $_.SideIndicator -eq -1 } | ForEach { Add-ADGroupMember -Identity $_.GroupDistinguishedName -Members $_.User }

    As a result for this command the user YYYY will be a member for all groups for the user XXXX belongs

    .LINK
    https://github.com/it-praktyk/Get-ADGroupsDifference

    .LINK
    https://www.linkedin.com/in/sciesinskiwojciech

    .NOTES
    AUTHOR: Wojciech Sciesinski, wojciech[at]sciesinski[dot]net
    KEYWORDS: PowerShell, Active Directory, Groups

    VERSION HISTORY
    - 0.3.0 - 2015-08-01 - The first version published on GitHub
    - 0.3.1 - 2015-08-01 - Help updated
    - 0.4.0 - 2016-08-22 - Scenarios when evaluated accounts are not members of any group added partially,
                           the function renamed from Get-ADGroupDifferences to Get-AdGroupsDifference
    - 0.4.1 - 2016-08-24 - Scenarios when evaluated accounts are not members of any group added partially,
                           TODO added, help updated
    - 0.4.2 - 2016-09-07 - Error with returning groups corrected
    - 0.4.3 - 2018-01-05 - Trailing spaces removed
    - 0.4.4 - 2018-08-09 - Mispelled variable name corrected - credits Ward Durossette
    - 0.4.5 - 2018-08-10 - Add GroupName property and hide CN/DN paths by default to improve table formatting
                           - credits Sebastian N. @megamorf
    - 0.4.6 - 2018-08-11 - Help aligned to the v. 0.4.5

    LICENSE
    Copyright (c) 2015-2016 Wojciech Sciesinski
    This function is licensed under The MIT License (MIT)
    Full license text: http://opensource.org/licenses/MIT

    TODO
    - add support for taking users from pipeline
    - add support to include/compare PrimaryGroup also
    - add verbose messages
    - add INPUTS, OUTPUS

  #>

    Param (
        [parameter(Mandatory = $true)]
        [alias("BaseUser")]
        [String]$ReferenceUser,
        [parameter(Mandatory = $true)]
        [alias("CurrentUser")]
        [String]$User,
        [parameter(Mandatory = $false)]
        [String]$DomainName,
        [parameter(Mandatory = $false)]
        [Switch]$IncludeEqual
    )

    BEGIN {

        if ($null -eq (Get-Module -name 'ActiveDirectory' -ErrorAction SilentlyContinue)) {

            Import-Module -Name 'ActiveDirectory' -ErrorAction Stop | Out-Null

        }

        if ($DomainName -eq $Null) {

            $DomainName = (Get-ADdomain -Current LoggedOnUser).DNSRoot

        }

        [String]$DomainController = (Get-ADDomainController -DomainName $DomainName -Discover).HostName

        $Results = @()

        # Define custom default view
        $defaultDisplaySet = 'ReferenceUser', 'User', 'GroupName', 'SideIndicator', 'SideIndicatorName'

        # Create the default property display set
        $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet(‘DefaultDisplayPropertySet’, [string[]]$defaultDisplaySet)

        $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)

    }

    PROCESS {

        $Error.Clear()

        Try {

            $ReferenceUserObject = Get-ADUser -Identity $ReferenceUser -Properties MemberOf, PrimaryGroup -server $DomainController

            $ReferenceUserGroups = $ReferenceUserObject | Select-Object -Property MemberOf -ExpandProperty MemberOf

            $CurrentUserObject = Get-ADUser -Identity $User -Properties MemberOf, PrimaryGroup -server $DomainController

            $CurrentUserGroups = $CurrentUserObject | Select-Object -Property MemberOf -ExpandProperty MemberOf

        }

        Catch {

            Write-Error -Message $error[0]

        }

        if ($Error.count -eq 0) {

            if ($null -eq $ReferenceUserGroups) {

                $ReferenceUserGroups = @()

            }
            elseif ($null -eq $CurrentUserGroups) {

                $CurrentUserGroups = @()

            }

            $Differences = @(Compare-Object -ReferenceObject $ReferenceUserGroups -DifferenceObject $CurrentUserGroups -IncludeEqual:$($IncludeEqual.IsPresent))

            ForEach ($Difference in $Differences) {

                $Result = New-Object PSObject

                $Result | Add-Member -type 'NoteProperty' -name ReferenceUser -value $ReferenceUser

                $Result | Add-Member -type 'NoteProperty' -name User -value $User

                $Result | Add-Member -type 'NoteProperty' -name GroupName -value ($Difference.InputObject -replace '^CN=|,.*$')

                $Result | Add-Member -type 'NoteProperty' -name GroupDistinguishedName -value $Difference.InputObject

                $Result | Add-Member -type 'NoteProperty' -Name GroupCanonicalName -Value $(ConvertFrom-DN ($Difference.InputObject))

                if (($Difference.SideIndicator).ToLower().Contains("<=".ToLower())) {

                    $Result | Add-Member -Type 'NoteProperty' -name SideIndicator -Value -1

                    $Result | Add-Member -Type 'NoteProperty' -Name SideIndicatorName -Value "Only ReferenceUser"

                }
                elseif (($Difference.SideIndicator).ToLower().Contains("=>".ToLower())) {

                    $Result | Add-Member -Type 'NoteProperty' -Name SideIndicator -Value 1

                    $Result | Add-Member -Type 'NoteProperty' -Name SideIndicatorName -Value "Only User"

                }
                else {

                    $Result | Add-Member -Type 'NoteProperty' -Name SideIndicator -Value 0

                    $Result | Add-Member -Type 'NoteProperty' -Name SidegIndicatorName -Value "Both users"

                }

                $Result.PSObject.TypeNames.Insert(0, 'ADUser.GroupDifferenceObject')

                $Result | Add-Member MemberSet PSStandardMembers $PSStandardMembers

                $Results += $Result
            }

        }

    }

    END {

        Return $Results

    }

}

function ConvertFrom-DN {

    #Based on: http://practical-admin.com/blog/convert-dn-to-canoincal-and-back/
    #Credit: Andrew
    #Corrected by Wojciech Sciesinski

    param ([string]$DN = (Throw '$DN is required!'))

    foreach ($item in ($DN.replace('\,', '~').split(","))) {

        switch -regex ($item.TrimStart().Substring(0, 3)) {

            "CN=" { $CN += , $item.replace("CN=", ""); $CN += '/'; continue }

            "OU=" { $OU += , $item.replace("OU=", ""); $OU += '/'; continue }

            "DC=" { $DC += $item.replace("DC=", ""); $DC += '.'; continue }

        }

    }

    $canonical = $dc.Substring(0, $dc.length - 1)

    if ($ou.count -gt 0) {

        for ($i = $ou.count; $i -ge 0; $i--) { $canonical += $ou[$i] }

    }

    if ($CN.count -gt 0) {

        for ($i = $CN.count; $i -ge 0; $i--) { $canonical += $CN[$i] }

    }

    return $canonical
}
