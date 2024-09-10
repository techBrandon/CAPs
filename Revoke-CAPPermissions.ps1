<#
.SYNOPSIS
Revoke delegated Graph PowerShell permissions from user
.DESCRIPTION
Removes the delegated permissions for Graph PowerShell from a specified account.
Modify the $userUPN variable with the UPN of the user to have permissions removed.
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
Connect-MgGraph -Scopes ("Application.ReadWrite.All", "Directory.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All")

# Microsoft Graph Command Line Tools aka Microsoft Graph PowerShell
$GraphCLT_SP = Get-MgServicePrincipal -Filter "appId eq '14d82eec-204b-4c2f-b7e8-296a70dab67e'"
$userObject = Get-MgUser -UserId $userUPN

$GraphPermissions = Get-MgOauth2PermissionGrant -All| Where-Object { ($_.clientId -eq $GraphCLT_SP.Id) -and ($_.PrincipalId -eq $userObject.Id) }

$GraphPermissions | ForEach-Object {Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id}

Disconnect-Graph | Out-Null
