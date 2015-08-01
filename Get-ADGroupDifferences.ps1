Function Get-ADGroupDifferences {
    
<#
    .SYNOPSIS
    Function intended for comparing Active Directory group membership between given user and another (reference) user
    
    .DESCRIPTION
    Using this function you can compare groups membership for two users Active Directory users. The first is reference user, the second is compared with it.  
  
    .PARAMETER ReferenceUser
    SAMAccount name of user that are used as source for comparison
  
    .PARAMETER User
    SAMAccount name of user that group membership comparison will be performed
  
    .PARAMETER DomainName
    Active Directory domain name - NETBIOS or FQDN - if not given than current domain for logged user is used
    
    .PARAMETER IncludeEqual
    If set to TRUE than also groups for which both users belong will be displayed
      
    .EXAMPLE
    Get-ADGroupDifferences -ReferenceUser XXXX -User YYYY
    
    ReferenceUser          : XXXX
    User                   : YYYY
    GroupDistinguishedName : CN=GroupA,OU=Groups NonSpecials,DC=domain,DC=local
    GroupCanonicalName     : domain.local/Groups NonSpecials/GroupA
    SideIndicator          : 1
    SideIndicatorName      : Only User

    ReferenceUser          : XXXX
    User                   : YYYY
    GroupDistinguishedName : CN=GroupB,OU=Groups NonSpecials,DC=domain,DC=local
    GroupCanonicalName     : domain.local/Groups NonSpecials/GroupB
    SideIndicator          : -1
    SideIndicatorName      : Only ReferenceUser

    ReferenceUser          : XXXX
    User                   : YYYY
    GroupDistinguishedName : CN=Group-007-License,OU=Groups Special,DC=domain,DC=local
    GroupCanonicalName     : domain.local/Groups Special/Group-007-License
    SideIndicator          : -1
    SideIndicatorName      : Only ReferenceUser

    .EXAMPLE
    Get-ADGroupDifferences -ReferenceUser XXXX -User YYYY | Where { $_.SideIndicator -eq -1 } | ForEach { Add-ADGroupMember -Identity $_.GroupDistinguishedName -Members $_.User }
    
    As a result for this command the user YYYY will be a member for all groups for the user XXXX belongs
    
    .LINK
    https://github.com/it-praktyk/Get-ADGroupDifferences
    
    .LINK
    https://www.linkedin.com/in/sciesinskiwojciech
          
    .NOTES
    AUTHOR: Wojciech Sciesinski, wojciech[at]sciesinski[dot]net
    KEYWORDS: PowerShell, Active Directory, Groups
    VERSION HISTORY
    0.3 - 2015-07-16 - The first version published on GitHub
    
    LICENSE
    This function is licensed under The MIT License (MIT)
    Full license text: http://opensource.org/licenses/MIT
    Copyright (c) 2015 Wojciech Sciesinski
    
    DISCLAIMER
    This script is provided AS IS without warranty of any kind. I disclaim all implied warranties including, without limitation,
    any implied warranties of merchantability or of fitness for a particular purpose. The entire risk arising out of the use or
    performance of the sample scripts and documentation remains with you. In no event shall I be liable for any damages whatsoever
    (including, without limitation, damages for loss of business profits, business interruption, loss of business information,
    or other pecuniary loss) arising out of the use of or inability to use the script or documentation. 
   
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
        [bool]$IncludeEqual = $false
        
    )
    
    BEGIN {
        
        
        if ((Get-Module -name 'ActiveDirectory' -ErrorAction SilentlyContinue) -eq $null) {
            
            Import-Module -Name 'ActiveDirectory' -ErrorAction Stop | Out-Null
            
        }
        
        
        
        If ($DomainName -eq $Null) {
            
            $DomainName = (Get-ADdomain -Current LoggedOnUser).DNSRoot
            
        }
        
        [String]$DomainController = (Get-ADDomainController -DomainName $DomainName -Discover).HostName
        
        $Results = @()
        
    }
    
    PROCESS {
        
        $ReferenceUserGroups = Get-AdUser $ReferenceUser -Properties memberof -server $DomainController | select memberof -ExpandProperty memberof
        
        $CurrentUserGroups = $(get-aduser $User  -Properties memberof -server $DomainController | select memberof -ExpandProperty memberof)
        
        $Differences = @(Compare-Object -ReferenceObject $ReferenceUserGroups -DifferenceObject $CurrentUserGroups -IncludeEqual:$IncludeEqual)
        
        ForEach ($Difference in $Differences) {
            
            $Result = New-Object PSObject
            
            $Result | Add-Member -type 'NoteProperty' -name ReferenceUser -value $ReferenceUser
            
            $Result | Add-Member -type 'NoteProperty' -name User -value $User
            
            $Result | Add-Member -type 'NoteProperty' -name GroupDistinguishedName -value $Difference.InputObject
            
            $Result | Add-Member -type 'NoteProperty' -Name GroupCanonicalName -Value $(ConvertFrom-DN ($Difference.InputObject))
            
            If (($Difference.SideIndicator).ToLower().Contains("<=".ToLower())) {
                
                $Result | Add-Member -Type 'NoteProperty' -name SideIndicator -Value -1
                
                $Result | Add-Member -Type 'NoteProperty' -Name SideIndicatorName -Value "Only ReferenceUser"
                
            }
            elseif (($Difference.SideIndicator).ToLower().Contains("=>".ToLower())) {
                
                $Result | Add-Member -Type 'NoteProperty' -Name SideIndicator -Value 1
                
                $Result | Add-Member -Type 'NoteProperty' -Name SideIndicatorName -Value "Only User"
                
            }
            Else {
                
                $Result | Add-Member -Type 'NoteProperty' -Name SideIndicator -Value 0
                
                $Result | Add-Member -Type 'NoteProperty' -Name SideIndicatorName -Value "Both users"
                
            }
            
            $Results += $Result
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
            
            "CN=" { $CN +=, $item.replace("CN=", ""); $CN += '/'; continue }
            
            "OU=" { $OU +=, $item.replace("OU=", ""); $OU += '/'; continue }
            
            "DC=" { $DC += $item.replace("DC=", ""); $DC += '.'; continue }
            
        }
        
    }
    
    $canonical = $dc.Substring(0, $dc.length - 1)
    
    If ($ou.count -gt 0) {
        
        for ($i = $ou.count; $i -ge 0; $i--) { $canonical += $ou[$i] }
        
    }
    
    If ($CN.count -gt 0) {
        
        for ($i = $CN.count; $i -ge 0; $i--) { $canonical += $CN[$i] }
        
    }
    
    return $canonical
}