<#
.SYNOPSIS
Reports on Conditional Access Policies
.DESCRIPTION
This script leverages Microsoft Graph PowerShell commands to report on Conditional Access Policies (CAPs) in a target tenant. 
The account used to run this script must be delegated read-only permissions to CAPs as well as other Directory objects.
This script will categorize tenant CAPs based on how they fit into Microsoft best practices.
.NOTES
Version: 1.2
Updated: 20240821
Author: Brandon Colley
Email: ColleyBrandon@pm.me
#>

# Required Graph permissions to run this script.
$graphScope = @(
'Policy.Read.All' #Required to run: Get-MgIdentityConditionalAccessPolicy
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

function Get-AdminRoleConfig{
    param(
        $CAPtargetingRoles
    )
    $default14Roles = @(
        '62e90394-69f5-4237-9190-012177145e10',
        '194ae4cb-b126-40b2-bd5b-6091b380977d',
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c',
        '29232cdf-9323-42fd-ade2-1d097af3e4de',
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9',
        '729827e3-9c14-49f7-bb1b-9608f156bbb8',
        'b0f54661-2d74-4c50-afa3-1ec803f12efe',
        'fe930be7-5e62-47db-91af-98c3a49a38b1',
        'c4e39bd9-1100-46d3-8c65-fb160da0071f',
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3',
        '158c047a-c907-4556-b7ef-446551a6b5f7',
        '966707d0-3269-4727-9be2-8c3a10f19b9d',
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13',
        'e8611ab8-c189-46e8-94e1-60213ab1f814'
    )
    $defaultCount = 0
    $nonDefaultCount = 0
    $includeCount = 0
    $includeCount = $CAPtargetingRoles.Conditions.Users.IncludeRoles.count
    
    ForEach ($role in ($CAPtargetingRoles.Conditions.Users.IncludeRoles)){
        if($default14Roles -contains $role){
            $defaultCount++
        }
        else{
            $nonDefaultCount++
        }
    }
    $return = [PSCustomObject]@{
        CAP_Name = $CAPtargetingRoles.DisplayName
        Total_Roles = $includeCount
        Default_Roles = "$defaultCount/14"
        Additional_Roles = $nonDefaultCount
    }
    $return
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

Write-Host -ForegroundColor DarkYellow "`nChecking for Misconfigured CAPs"
Write-Host -ForegroundColor Green "`nMFA Policies that target Admin roles should include the 14 default roles and any other role the environment deems privileged."
ForEach ($adminCAP in $CAPMFAforAdmins){
    Get-AdminRoleConfig $adminCAP
}
