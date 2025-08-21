<#
.SYNOPSIS
Reports on Conditional Access Policies
.DESCRIPTION
This script leverages Microsoft Graph PowerShell commands to report on Conditional Access Policies (CAPs) in a target tenant. 
The account used to run this script must be delegated read-only permissions to CAPs.
This script will categorize tenant CAPs based on how they fit into Microsoft best practices.
.NOTES
Version: 1.4
Updated: 20250821
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

# Report on high level policy status
Write-Host -ForegroundColor DarkYellow "`nConditional Access Statistics"
Write-Host $ConditionalAccessPolicyArray.count "Conditional Access policies are configured for the tenant"
Write-Host ($ConditionalAccessPolicyArray | Where-Object DisplayName -like 'Microsoft-managed:*').count "are Microsoft Managed and are set to Report-only"
Write-Host ($ConditionalAccessPolicyArray | Where-Object state -eq enabled).count "are On (enabled)"
Write-Host ($ConditionalAccessPolicyArray | Where-Object state -eq enabledForReportingButNotEnforced).count "are set to Report-only"
Write-Host ($ConditionalAccessPolicyArray | Where-Object state -eq disabled).count "are Off (disabled)"

Write-Host -ForegroundColor DarkYellow "`nAll Conditional Access Policies"
$ConditionalAccessPolicyArray| Format-Table DisplayName,State,CreatedDateTime,ModifiedDateTime

# Variables to distinguish and translate Authentication Strengths
$PhishResist = @{
    "windowsHelloForBusiness" = "Windows Hello For Business / Platform Credential"
    "fido2" = "Passkeys (FIDO2)"
    "x509CertificateMultiFactor" = "Certificate-based Authentication (Multifactor)"
}
$Passwordless = @{
    "deviceBasedPush" = "Microsoft AUthenticator (Phone Sign-in)"
}
$Multifactor = @{
    "temporaryAccessPassOneTime" = "Temporary Access Pass (One-time use)"
    "temporaryAccessPassMultiUse" = "Temporary Access Pass (Multi-use)"
    "password,microsoftAuthenticatorPush" = "Password + Microsoft Authenticator (Push Notifcation)"
    "password,softwareOath" = "Password + Software OATH token"
    "password,hardwareOath" = "Password + Hardware OATH token"
    "password,sms" = "Password + SMS"
    "password,voice" = "Password + Voice"
    "federatedMultiFactor" = "Federated Multifactor"
    "microsoftAuthenticatorPush,federatedSingleFactor" = "Federated Single factor + Microsoft Authenticator (Push Notification)"
    "softwareOath,federatedSingleFactor" = "Federated Single factor + Software OATH token"
    "hardwareOath,federatedSingleFactor" = "Federated Single factor + Hardware OATH token"
    "sms,federatedSingleFactor" = "Federated Single factor + SMS"
    "voice,federatedSingleFactor" = "Federated Single factor + Voice"
}
$Singlefactor = @{
    "sms" = "SMS"
    "password" = "Password"
    "federatedSingleFactor" = "Federated Single factor"
    "QRCodePin" = "QR code (Preview)"
}

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
    if(($CAPolicy.Conditions.AdditionalProperties.Values.Values -or $CAPolicy.Conditions.AuthenticationFlows.TransferMethods) -and $CAPolicy.GrantControls.BuiltInControls -eq 'block'){
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
        '62e90394-69f5-4237-9190-012177145e10', # Global Administrator
        'fe930be7-5e62-47db-91af-98c3a49a38b1', # User Administrator
        '729827e3-9c14-49f7-bb1b-9608f156bbb8', # Helpdesk Administrator
        'b0f54661-2d74-4c50-afa3-1ec803f12efe', # Billing Administrator
        '29232cdf-9323-42fd-ade2-1d097af3e4de', # Exchange Administrator
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', # SharePoint Administrator
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', # Application Administrator
        '194ae4cb-b126-40b2-bd5b-6091b380977d', # Security Administrator
        'e8611ab8-c189-46e8-94e1-60213ab1f814', # Privileged Role Administrator
        '158c047a-c907-4556-b7ef-446551a6b5f7', # Cloud Application Administrator
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', # Conditional Access Administrator
        'c4e39bd9-1100-46d3-8c65-fb160da0071f', # Authentication Administrator
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', # Privileged Authentication Administrator
        '966707d0-3269-4727-9be2-8c3a10f19b9d'  # Password Administrator
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
    $strongMFA = $PhishResist + $Passwordless

    ForEach ($policy in $CAPSusingAuthStrength){
        $passFail = "Pass"
        $phishCount = 0
        $passwordlessCount = 0
        $multifactorCount = 0
        $singlefactorCount = 0
        ForEach ($authMethod in ($policy.GrantControls.AuthenticationStrength.AllowedCombinations)){
            if($strongMFA.Keys -notcontains $authMethod){
                $passFail = "Fail"
            }
            if($PhishResist.Keys -contains $authMethod){
                $phishCount ++
            }
            if($Passwordless.Keys -contains $authMethod){
                $passwordlessCount ++
            }
            if($Multifactor.Keys -contains $authMethod){
                $multifactorCount ++
            }
            if($Singlefactor.Keys -contains $authMethod){
                $singlefactorCount ++
            }
        }
        $returnStrength = [PSCustomObject]@{
            CAP_Name = $policy.DisplayName
            Total_Methods = $policy.GrantControls.AuthenticationStrength.AllowedCombinations.count
            Status = $passFail
            PhishResistant = $phishCount
            Passwordless = $passwordlessCount
            Multifactor = $multifactorCount
            Singlefactor = $singlefactorCount
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
Write-Host -ForegroundColor Green "`nPolicies that secure Security Info Registration"
$CAPSecureRegistration.DisplayName

Write-Host -ForegroundColor DarkYellow "`nChecking for Misconfigured CAPs"
Write-Host -ForegroundColor Green "`nMFA Policies that target Admin roles should include the 14 default roles and any other role the environment deems privileged."
Get-AdminRoleConfig $CAPMFAforAdmins | Out-Host

Write-Host -ForegroundColor Green "`nMFA Policies that utilize Authentication Strength should use passwordless or phishing-resistant methods of MFA."
Compare-AuthStrength $CAPAuthStrength | Format-Table 
