Welcome!
This repo is dedicated to reporting on Microsoft Entra Conditional Access.

The Invoke-CAPReview.ps1 script requires an account that has been delegated read-only permissions to the Graph Command Line Tools (aka Microsoft Graph PowerShell)
These permissions (and more) are automatically delegated to highly privileged Entra ID roles however, best practice would require a dedicated account granted only the required permissions.
The Grant-CAPPermissions.ps1 is a very simple script that can delegate these permissions. Set the $userUPN variable and run the script as Cloud Application Administrator or equivalent.

Script output reports on statistics and lists all Conditional Access Policies
![image](https://github.com/user-attachments/assets/ed66d16e-2d7f-4683-8123-889bddea9351)

It then categorizes the policies into 9 of Microsoft's best practice categories

![image](https://github.com/user-attachments/assets/2f1440c8-dc0f-480b-8c9a-7446862755de)

Finally, the script begins checking for misconfigured policies
![image](https://github.com/user-attachments/assets/dbb8d5d7-eea4-4602-a288-77db40ccb00c)
