# Get-ADGroupsDifference

## SYNOPSIS
PowerShell function intended to compare group membership for two Active Directory users.

## DESCRIPTION
Using this function you can compare groups membership for two users Active Directory users.    
The first is reference user, the second is compared with it and as the result groups different for both users will be displayed.
	
## PARAMETERS  
### ReferenceUser
Active Directory user object used as source for comparison - reference user

The acceptable values for this parameter are:
-- A Distinguished Name
-- A GUID (objectGUID)
-- A Security Identifier (objectSid)
-- A SAM Account Name (sAMAccountName)

### User
Active Directory user object for which group membership comparison will be performed

The acceptable values for this parameter are:
-- A Distinguished Name
-- A GUID (objectGUID)
-- A Security Identifier (objectSid)
-- A SAM Account Name (sAMAccountName)

### DomainName
Active Directory domain name - NETBIOS or FQDN - if not given than current domain for logged user is used.

### IncludeEqual
If used set to TRUE than also groups for which both users belong will be displayed. Default value is $False

## EXAMPLES

### EXAMPLE 1
```powershell
Get-ADGroupsDifference -ReferenceUser XXXX -User YYYY

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
```

### EXAMPLE 2
```powershell   
Get-ADGroupsDifference -ReferenceUser XXXX -User YYYY | Where { $_.SideIndicator -eq -1 } | ForEach { Add-ADGroupMember -Identity $_.GroupDistinguishedName -Members $_.User }
```

As the result for this command the user YYYY will be a member for all groups for the user XXXX belongs

### BASE REPOSITORY
https://github.com/it-praktyk/Get-ADGroupsDifference


## NOTES
AUTHOR: Wojciech Sciesinski, wojciech[at]sciesinski[dot]net  
KEYWORDS: PowerShell, Active Directory, Groups

## LICENSE
Copyright (c) 2015-2016 Wojciech Sciesinski  
This function is licensed under The MIT License (MIT)  
Full license text: http://opensource.org/licenses/MIT

## VERSIONS HISTORY
- 0.3.0 - 2015-08-01 - The first version published on GitHub
- 0.3.1 - 2015-08-01 - Help updated
- 0.4.0 - 2016-08-22 - Scenarios when evaluated accounts are not members of any group added partially, the function renamed from Get-ADGroupDifferences to Get-AdGroupsDifference
- 0.4.1 - 2016-08-24 - Scenarios when evaluated accounts are not members of any group added partially, TODO added, help updated
