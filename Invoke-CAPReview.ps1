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
[array]$CAPMFAforGuests = @()
[array]$CAPRisk = @()
[array]$CAPAppProtection = @()
[array]$CAPDeviceCompliance = @()
[array]$CAPUsingLocations = @()
[array]$CAPRestrictAdminPortal = @()
[array]$CAPMFAforDeviceJoin = @()
[array]$CAPBlockAuthFlow = @()
[array]$CAPTargetAllResources = @()
[array]$CAPSecureRegistration = @()
[array]$CAPAuthStrength = @()

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
    if((($CAPolicy.GrantControls.BuiltInControls -contains 'mfa') -or ($CAPolicy.GrantControls.AuthenticationStrength.Id)) -and ($CAPolicy.Conditions.Users.IncludeGuestsOrExternalUsers.GuestOrExternalUserTypes)){
        $CAPMFAforGuests += $CAPolicy
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
    if($CAPolicy.Conditions.AdditionalProperties.Values.Values -and $CAPolicy.GrantControls.BuiltInControls -eq 'block'){
        $CAPBlockAuthFlow += $CAPolicy
    }
    if(($CAPolicy.Conditions.Applications.IncludeApplications -eq 'All') -and ($CAPolicy.Conditions.Users.IncludeUsers -contains 'All')){
        $CAPTargetAllResources += $CAPolicy
    }
    if($CAPolicy.Conditions.Applications.IncludeUserActions -like '*registersecurityinfo*'){
        $CAPSecureRegistration += $CAPolicy
    }
    if($CAPolicy.GrantControls.AuthenticationStrength.Id){
        $CAPAuthStrength += $CAPolicy
    }
} 

function Get-AdminRoleConfig{
    param(
        $CAPStargetingRoles
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
    ForEach ($policy in $CAPStargetingRoles){
        $defaultCount = 0
        $nonDefaultCount = 0
        $includeCount = 0
        $includeCount = $policy.Conditions.Users.IncludeRoles.count
        
        ForEach ($role in ($policy.Conditions.Users.IncludeRoles)){
            if($default14Roles -contains $role){
                $defaultCount++
            }
            else{
                $nonDefaultCount++
            }
        }
        $returnAdmin = [PSCustomObject]@{
            CAP_Name = $policy.DisplayName
            Total_Roles = $includeCount
            Default_Roles = "$defaultCount/14"
            Additional_Roles = $nonDefaultCount
        }
        $returnAdmin
    }
}

function Compare-AuthStrength{
    param(
        $CAPSusingAuthStrength
    )
    $strongMFA = @(
        'fido2',
        'windowsHelloForBusiness',
        'x509CertificateMultiFactor',
        'deviceBasedPush'
    )
    ForEach ($policy in $CAPSusingAuthStrength){
        $passFail = "Pass"
        ForEach ($authMethod in ($policy.GrantControls.AuthenticationStrength.AllowedCombinations)){
            if($strongMFA -notcontains $authMethod){
                $passFail = "Fail"
            }
        }
        $returnStrength = [PSCustomObject]@{
            CAP_Name = $policy.DisplayName
            Number_of_Methods = $policy.GrantControls.AuthenticationStrength.AllowedCombinations.count
            Status = $passFail
        }
        $returnStrength
    }
}

Write-Host -ForegroundColor DarkYellow "Categorize Policies:"
Write-Host -ForegroundColor Green "`nPolicies that Block Legacy Authentication"
$CAPBlockLegacyAccess.DisplayName
Write-Host -ForegroundColor Green "`nPolicies that enforce MFA for Administrators"
$CAPMFAforAdmins.DisplayName
Write-Host -ForegroundColor Green "`nPolicies that enforce MFA for Users"
$CAPMFAforUsers.DisplayName
Write-Host -ForegroundColor Green "`nPolicies that enforce MFA for Guests"
$CAPMFAforGuests.DisplayName
Write-Host -ForegroundColor Green "`nPolicies that affect Risky Users"
$CAPRisk.DisplayName
Write-Host -ForegroundColor Green "`nPolicies that require Approved Client or App Protection"
$CAPAppProtection.DisplayName
Write-Host -ForegroundColor Green "`nPolicies that require Device Compliance"
$CAPDeviceCompliance.DisplayName
Write-Host -ForegroundColor Green "`nPolicies that restrict access by Location"
$CAPUsingLocations.DisplayName
Write-Host -ForegroundColor Green "`nPolicies that restrict access to the Admin Portal"
$CAPRestrictAdminPortal.DisplayName
Write-Host -ForegroundColor Green "`nPolicies that require MFA for Device Join"
$CAPMFAforDeviceJoin.DisplayName
Write-Host -ForegroundColor Green "`nPolicies that block Authentication Flows"
$CAPBlockAuthFlow.DisplayName
Write-Host -ForegroundColor Green "`nPolicies that target All Resources and All Users"
$CAPTargetAllResources.DisplayName
Write-Host -ForegroundColor Green "`nPolicies that secure Secuirity Info Registration"
$CAPSecureRegistration.DisplayName

Write-Host -ForegroundColor DarkYellow "`nChecking for Misconfigured CAPs"
Write-Host -ForegroundColor Green "`nMFA Policies that target Admin roles should include the 14 default roles and any other role the environment deems privileged."
Get-AdminRoleConfig $CAPMFAforAdmins | Out-Host

Write-Host -ForegroundColor Green "`nMFA Policies that utilize Authentication Strength should use passwordless or phishing-resistant methods of MFA."
Compare-AuthStrength $CAPAuthStrength | Out-Host