Welcome!
This repo is dedicated to reporting on Microsoft Entra Conditional Access.

The Invoke-CAPReview.ps1 script requires an account that has been delegated read-only permissions to the Graph Command Line Tools (aka Microsoft Graph PowerShell)
These permissions (and more) are automatically delegated to highly privileged Entra ID roles however, best practice would require a dedicated account granted only the required permissions.
The Grant-CAPPermissions.ps1 is a very simple script that can delegate these permissions. Set the $userUPN variable and run the script as Cloud Application Administrator or equivalent.
