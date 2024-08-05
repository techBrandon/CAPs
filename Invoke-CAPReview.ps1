<#
.SYNOPSIS
Reports on Conditional Access Policies
.DESCRIPTION
This script leverages Microsoft Graph PowerShell commands to report on Conditional Access Policies (CAPs) in a target tenant. 
The account used to run this script must be delegated read-only permissions to CAPs as well as other Directory objects.
This script will categorize tenant CAPs based on how they fit into Microsoft best practices.
.NOTES
Version: 1.1
Updated: 20240801
Author: Brandon Colley
Email: ColleyBrandon@pm.me
#>

# Required Graph permissions to run this script.
$graphScope = @(
'DeviceManagementConfiguration.Read.All', #Required to run: Get-MgDeviceManagementDeviceConfiguration
'Directory.Read.All', # User, Group, and Device queries
'IdentityProvider.Read.All', #Required to run: Get-MgIdentityProvider
'Policy.Read.All', #Required to run: Get-MgIdentityConditionalAccessPolicy
'AuditLog.Read.All', #Required to run: Get-MgReportAuthenticationMethodUserRegistrationDetail
'UserAuthenticationMethod.Read.All' # Required to run: Get-MgUserAuthenticationMethod    
)

# Prompt for and authenticate to tenant
Write-Host -ForegroundColor Blue -BackgroundColor White 'Connecting to Graph using the existing token or by using the credentials selected in the logon prompt.'
Connect-MgGraph -Scopes $graphScope

# Gather all policy data to be parsed in script. Note, this will not include policies with preview features.
[array]$ConditionalAccessPolicyArray = Get-MgIdentityConditionalAccessPolicy -All -Property *

# Report on policy status
Write-Host -ForegroundColor DarkYellow "`nConditional Access Statistics"
Write-Host $ConditionalAccessPolicyArray.count "Conditional Access policies are configured for the tenant"
Write-Host ($ConditionalAccessPolicyArray | Where-Object DisplayName -like 'Microsoft-managed:*').count "are Microsoft Managed and are set to Report-only"
Write-Host ($ConditionalAccessPolicyArray | Where-Object state -eq enabled).count "are On (enabled)"
Write-Host ($ConditionalAccessPolicyArray | Where-Object state -eq enabledForReportingButNotEnforced).count "are set to Report-only"
Write-Host ($ConditionalAccessPolicyArray | Where-Object state -eq disabled).count "are Off (disabled)"

Write-Host -ForegroundColor DarkYellow "`nAll Conditional Access Policies"
$ConditionalAccessPolicyArray| Format-Table DisplayName,State,CreatedDateTime,ModifiedDateTime

# Stage arrays to be filled for each subsection category
[array]$CAPBlockLegacyAccess = @()
[array]$CAPMFAforAdmins = @()
[array]$CAPMFAforUsers = @()
[array]$CAPRisk = @()
[array]$CAPAppProtection = @()
[array]$CAPDeviceCompliance = @()
[array]$CAPUsingLocations = @()
[array]$CAPRestrictAdminPortal = @()
[array]$CAPMFAforDeviceJoin = @()

ForEach ($CAPolicy in $ConditionalAccessPolicyArray){
    if((($CAPolicy.Conditions.ClientAppTypes -contains 'exchangeActiveSync') -or ($CAPolicy.Conditions.ClientAppTypes -contains 'other')) -and (($CAPolicy.Conditions.ClientAppTypes -notcontains 'browser') -and ($CAPolicy.Conditions.ClientAppTypes -notcontains 'mobileAppsAndDesktopClients')) -and ($CAPolicy.GrantControls.BuiltInControls -eq 'block')){
        $CAPBlockLegacyAccess += $CAPolicy
    }
    if((($CAPolicy.GrantControls.BuiltInControls -contains 'mfa') -or ($CAPolicy.GrantControls.AuthenticationStrength.Id)) -and ($CAPolicy.Conditions.Users.IncludeRoles)){
        $CAPMFAforAdmins += $CAPolicy
    }
    if((($CAPolicy.GrantControls.BuiltInControls -contains 'mfa') -or ($CAPolicy.GrantControls.AuthenticationStrength.Id)) -and (($CAPolicy.Conditions.Users.IncludeUsers -contains 'All') -or ($CAPolicy.Conditions.Users.IncludeGroups))){
        $CAPMFAforUsers += $CAPolicy
    }
    if(($CAPolicy.Conditions.SignInRiskLevels) -or ($CAPolicy.Conditions.UserRiskLevels)){
        $CAPRisk += $CAPolicy
    }
    if(($CAPolicy.Conditions.Platforms.IncludePlatforms -contains 'Android') -and ($CAPolicy.Conditions.Platforms.IncludePlatforms -contains 'iOS')){
        $CAPAppProtection += $CAPolicy
    }
    if(($CAPolicy.GrantControls.BuiltInControls -contains 'compliantDevice') -or ($CAPolicy.GrantControls.BuiltInControls -contains 'domainJoinedDevice')){
        $CAPDeviceCompliance += $CAPolicy
    }
    if($CAPolicy.Conditions.Locations.IncludeLocations -or $CAPolicy.Conditions.Locations.ExcludeLocations){
        $CAPUsingLocations += $CAPolicy
    }
    if($CAPolicy.Conditions.Applications.IncludeApplications -contains 'MicrosoftAdminPortals'){
        $CAPRestrictAdminPortal += $CAPolicy
    }
    if($CAPolicy.Conditions.Applications.IncludeUserActions -like '*registerdevice*'){
        $CAPMFAforDeviceJoin += $CAPolicy
    }
} 

Write-Host -ForegroundColor DarkYellow "Categorize Policies:"
Write-Host -ForegroundColor Green "`nPolicies that block Legacy Authentication"
$CAPBlockLegacyAccess.DisplayName
Write-Host -ForegroundColor Green "`nPolicies that enforce MFA for Administrators"
$CAPMFAforAdmins.DisplayName
Write-Host -ForegroundColor Green "`nPolicies that enforce MFA for Users"
$CAPMFAforUsers.DisplayName
Write-Host -ForegroundColor Green "`nPolicies that affect risky users"
$CAPRisk.DisplayName
Write-Host -ForegroundColor Green "`nPolicies that require approved client or app protection"
$CAPAppProtection.DisplayName
Write-Host -ForegroundColor Green "`nPolicies that require device compliance"
$CAPDeviceCompliance.DisplayName
Write-Host -ForegroundColor Green "`nPolicies that restrict access by location"
$CAPUsingLocations.DisplayName
Write-Host -ForegroundColor Green "`nPolicies that restrict access to the admin portal"
$CAPRestrictAdminPortal.DisplayName
Write-Host -ForegroundColor Green "`nPolicies that require MFA for device join or registration"
$CAPMFAforDeviceJoin.DisplayName