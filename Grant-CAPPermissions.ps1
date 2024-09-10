<#
.SYNOPSIS
Delegate an account Graph PowerShell permissions
.DESCRIPTION
Grants an account the permissions required to read Conditional Access using Graph PowerShell.
Modify the $userUPN variable with the UPN of the user to be granted permissions.
This script must be run as an account with the Cloud Application Administrator role or equivalent.
This script requires the Microsoft.Graph Module. 
Install-Module -Name Microsoft.Graph
.NOTES
Version: 1.1
Updated: 20240805
Author: Brandon Colley
Email: ColleyBrandon@pm.me
#>

# MODIFY THIS VARIABLE
$userUPN = 'username@tenant'

# If this command fails then you aren't running from an account granted the required level of permissions.
Connect-MgGraph -Scopes ("User.ReadBasic.All Application.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All")

# Microsoft Graph Command Line Tools aka Microsoft Graph PowerShell
$GraphCLT_SP = Get-MgServicePrincipal -Filter "appId eq '14d82eec-204b-4c2f-b7e8-296a70dab67e'"
# Microsoft Graph API
$GraphAPI_SP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$userObject = Get-MgUser -UserId $userUPN

New-MgOauth2PermissionGrant -ResourceId $GraphAPI_SP.Id -Scope 'Policy.Read.All' -ClientId $GraphCLT_SP.Id -ConsentType "Principal" -PrincipalId $userObject.Id

Disconnect-Graph | Out-Null
