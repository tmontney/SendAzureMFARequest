#requires -Modules CredentialManager, Microsoft.Graph.Applications

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String]
    $TenantID,
    [Parameter(Mandatory = $true)]
    [String]
    $ClientID, # Requires Application.ReadWrite.All
    [Parameter(Mandatory = $true)]
    [String]
    $TargetEmailAddress,
    [Parameter(Mandatory = $false)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]
    $Certificate = $null,
    [Parameter(Mandatory = $false)]
    [Switch]
    $UseOTP, # Placeholder
    [Parameter(Mandatory = $false)]
    [Switch]
    $InteractiveLogon
)

function Get-MgGraphApplicationSecret {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $ClientID,
        [Parameter(Mandatory = $false)]
        [Switch]
        $ByServicePrincipal,
        [Parameter(Mandatory = $false)]
        [Guid]
        $KeyID = [Guid]::Empty,
        [Parameter(Mandatory = $false)]
        [Switch]
        $ValidOnly
    )

    # Use this instead of Get-MgServicePrincipal: https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/1849
    if (-not $ByServicePrincipal) {
        $Result = Invoke-MgGraphRequest -Method "GET" -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$ClientID'" -ErrorAction Stop # Could fail due to permissions issue
    }
    else {
        $Result = Invoke-MgGraphRequest -Method "GET" -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$ClientID'" -ErrorAction Stop # Could fail due to permissions issue
    }
    
    if ($Result["value"]) {
        $PasswordCredentials = $Result["value"][0]["passwordCredentials"]
        if ($ValidOnly) 
        { $PasswordCredentials = $PasswordCredentials | Where-Object { (Get-Date) -lt $_["endDateTime"] } }

        if ($KeyID -ne [Guid]::Empty)
        { $PasswordCredentials = $PasswordCredentials | Where-Object { [Guid]$_.keyId -eq $KeyID } }

        return $PasswordCredentials
    }

    Write-PSFMessage -Level Error -Message "No applications found by the specified client ID"
}

function Set-MgGraphServicePrincipalPassword {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $ClientID,
        [Parameter(Mandatory = $false)]
        [DateTime]
        $EndDate = (Get-Date).AddDays(30),
        [Parameter(Mandatory = $false)]
        [Switch]
        $NoWait
    )

    if ($EndDate -lt (Get-Date)) {
        Write-PSFMessage -Level Error -Message "'EndDate' must be greater than the current date!"
        return
    }

    Write-PSFMessage -Level Verbose -Message "Creating service principal password ($ClientID`_$env:COMPUTERNAME`_$env:USERNAME)"

    $spId = (Get-MgServicePrincipal -Filter "AppId eq '$ClientID'").Id
    $params = @{
        "PasswordCredential" = @{
            "DisplayName" = "$ClientID`_$env:COMPUTERNAME`_$env:USERNAME"
            "EndDateTime" = $EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
    }
    $Result = Add-MgServicePrincipalPassword -ServicePrincipalId $spId -BodyParameter $params
    
    # If you use this password immediately after creation, you'll get an "Invalid client secret provided" error
    # Get-MgGraphApplicationSecret returns normally immediately after creation
    # Seems waiting a few seconds lets it process
    if (-not $NoWait)
    { Start-Sleep -Seconds 5 }

    return [PSCredential]::new($Result.KeyId, (ConvertTo-SecureString -String $Result.SecretText -AsPlainText -Force))
}

# This will return an object which contains a few characters of the original secret
# Just like from the Azure portal, you only get the secret at creation time

function Connect-AzureADNotificationsSvc {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [PSCredential]
        $ApplicationSecret
    )

    if ($Global:AAD_NOTF_ACCESSTOKEN -and ((Get-Date) -lt $Global:AAD_NOTF_ACCESSTOKEN_EXPIRES)) {
        Write-PSFMessage -Level Verbose -Message "Will be reusing the access token since it's still valid"
        return
    }
    else {
        Write-PSFMessage -Level Host -Message "Connecting to adnotifications.windowsazure.com..."

        $body = @{
            "resource"      = "https://adnotifications.windowsazure.com/StrongAuthenticationService.svc/Connector"
            "client_id"     = $Script:AAD_MFA_APPID
            "client_secret" = $($ApplicationSecret.GetNetworkCredential().Password)
            "grant_type"    = "client_credentials"
            "scope"         = "openid"
        }
    
        $Global:AAD_NOTF_ACCESSTOKEN = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantID/oauth2/token" -Method "POST" -Body $body -ErrorAction Stop
        $Global:AAD_NOTF_ACCESSTOKEN_EXPIRES = (Get-Date).AddSeconds($Global:AAD_NOTF_ACCESSTOKEN.expires_in)
    }
}

function Invoke-AzureMFARequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $TargetEmailAddress,
        [Parameter(Mandatory = $true)]
        [PSCustomObject]
        $AccessToken,
        [Parameter(Mandatory = $false)]
        [Switch]
        $UseOtp # Placeholder
    )

    if ($UseOtp)
    { Write-PSFMessage -Level Critical -Message "'UseOtp' is not implemented"; return }

    Write-PSFMessage -Level Host -Message "Invoking MFA request to user $TargetEmailAddress..."

    # Not required to be unique, but could help with troubleshooting
    $ContextID = [Guid]::NewGuid().ToString().ToLower()

    # No support for number matching https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-number-match#nps-extension
    $XML = @"
<BeginTwoWayAuthenticationRequest>
    <Version>1.0</Version>
    <UserPrincipalName>$TargetEmailAddress</UserPrincipalName>
    <Lcid>en-us</Lcid>
    <AuthenticationMethodProperties
        xmlns:a="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
        <a:KeyValueOfstringstring>
            <a:Key>OverrideVoiceOtp</a:Key>
            <a:Value>true</a:Value>
        </a:KeyValueOfstringstring>
        <a:KeyValueOfstringstring>
            <a:Key>OverrideNumberMatchingWithOTP</a:Key>
            <a:Value>$($UseOtp.IsPresent.ToString().ToLower())</a:Value>
        </a:KeyValueOfstringstring>
    </AuthenticationMethodProperties>
    <ContextId>$ContextID</ContextId>
    <SyncCall>true</SyncCall>
    <RequireUserMatch>false</RequireUserMatch>
    <CallerName>radius</CallerName>
    <CallerIP>UNKNOWN:</CallerIP>
</BeginTwoWayAuthenticationRequest>
"@

    Write-PSFMessage -Level Verbose -Message "Context ID is $ContextID"

    $headers = @{"Authorization" = "Bearer $($AccessToken.access_token)" }
    $obj = Invoke-RestMethod -Uri "https://adnotifications.windowsazure.com/StrongAuthenticationService.svc/Connector/BeginTwoWayAuthentication" -Method "POST" -Headers $headers -Body $XML -ContentType "application/xml" -ErrorAction Stop

    # This could return a string value 'challenge'. Although this might mean the user is already authenticated, the user will not have received a MFA notification.
    return $obj.BeginTwoWayAuthenticationResponse.AuthenticationResult -eq $true # What about timeouts?
}

$Script:AAD_MFA_APPID = "981f26a1-7f43-403b-a875-f8b09b8cd720"
$Script:AAD_CERT_CN = $ClientID # Must match this exactly to find the certificate to authenticate with

# Can easily generate a self-signed cert by doing the following:
# ----- $cert = New-SelfSignedCertificate -FriendlyName "MyMFAApp" -Subject "{app-client-id}" -CertStoreLocation "cert:\CurrentUser\My" -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"
# ----- Export-Certificate -Cert $cert -FilePath "$env:USERPROFILE\Desktop\cert.crt"

if (-not $Certificate -and -not $InteractiveLogon) {
    # A certificate uploaded to the Azure App Registration
    $Certificate = Get-ChildItem -Path "Cert:\CurrentUser\My" | Where-Object { $_.Subject -eq "CN=$Script:AAD_CERT_CN" } | Sort-Object "NotBefore" -Descending | Select-Object -First 1
    if (-not $Certificate) {
        Write-PSFMessage -Level Error -Message "No certificate found where the common name is equal to the app's client ID"
        return
    }
}

Write-PSFMessage -Level Host -Message "Connecting to Microsoft Graph..."
if ($InteractiveLogon)
{ Connect-MgGraph -NoWelcome -ErrorAction Stop }
else
{ Connect-MgGraph -TenantId $TenantID -ClientId $ClientID -Certificate $Certificate -NoWelcome -ErrorAction Stop }

$ServicePrincipalCredential = Get-StoredCredential -Target $Script:AAD_MFA_APPID -ErrorAction SilentlyContinue
if (-not $ServicePrincipalCredential) {
    Write-PSFMessage -Level Verbose -Message "No service principal password was found in credential manager"

    $ServicePrincipalCredential = Set-MgGraphServicePrincipalPassword -ClientID $Script:AAD_MFA_APPID -ErrorAction Stop
    [void](New-StoredCredential -Target $Script:AAD_MFA_APPID -Credentials $ServicePrincipalCredential -Persist LocalMachine)
}
else {
    if (-not (Get-MgGraphApplicationSecret -ClientID $Script:AAD_MFA_APPID -KeyID $ServicePrincipalCredential.UserName -ByServicePrincipal)) {
        Write-PSFMessage -Level Verbose -Message "Service principal password in credential manager was not found in Azure (possibly expired)"

        $ServicePrincipalCredential = Set-MgGraphServicePrincipalPassword -ClientID $Script:AAD_MFA_APPID -ErrorAction Stop
        [void](New-StoredCredential -Target $Script:AAD_MFA_APPID -Credentials $ServicePrincipalCredential -Persist LocalMachine)
    }
}

Connect-AzureADNotificationsSvc -ApplicationSecret $ServicePrincipalCredential
Invoke-AzureMFARequest -TargetEmailAddress $TargetEmailAddress -AccessToken $Global:AAD_NOTF_ACCESSTOKEN

if (-not $InteractiveLogon)
{ [void](Disconnect-MgGraph) }