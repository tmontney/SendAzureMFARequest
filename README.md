# Overview
This PowerShell script allows you to send a manual MFA notification (received through the Microsoft Authenticator app). Primary application for this is verifying a user's identity, such as for a password reset.

# Requirements
- PowerShell 5.1 (or higher)
- The following modules
  - [PSFramework](https://psframework.org/) (for logging, can switch to built-in `Write-Output`/`Write-Host` cmdlets if you don't want to rely on it)
  - [CredentialManager](https://github.com/davotronic5000/PowerShell_Credential_Manager) (stores the MFA service principal password needed for adnotifications.windowsazure.com)
  - [Microsoft.Graph.Applications](https://github.com/microsoftgraph/msgraph-sdk-powershell) (gets/sets the service principal password)
- Microsoft 365 Global Admin

# Azure App Registration
The app registration requires API permission `Application.ReadWrite.All`. Although this script defaults to certification authentication, it does support interactive. If you do use certificate authentication, it expects a certificate with common name of the app's client ID. (Modify `$Script:AAD_CERT_CN` if you want it to be something else.) When the script starts, it will automatically grab the most recent certificate (in your user's personal store) with that criteria for authentication.

# MFA Service Principal
Again, you'll need to be a global admin so passwords can be set. It's possible there's a way to delegate permissions, but I haven't looked into it much (and I don't know that would affect this undocumented resource or the risks involved). If you want multiple users (such as helpdesk) to be able to issue requests, you can increase the default value of the `EndDate` parameter in `Set-MgGraphServicePrincipalPassword`. Otherwise, it would probably be best to put this behind a web app (**particularly because the app requires `Application.ReadWrite.All`**).

When the script runs, it will check if there's a stored credential (in Credential Manager) with the name of the MFA app's client ID. It appropriately sets a new one if it doesn't exist or the existing password expired. (These passwords, in Azure, don't delete themselves when they expire, and the script doesn't automatically remove them.)

# Partner Center
One of the resources below (comments section) makes reference to needing a [Microsoft Partner Center](https://partner.microsoft.com/en-US/) account. While creating an account is free, it's unnecessary. (Perhaps this was required when using the, soon to be deprecated, [MSOnline](https://learn.microsoft.com/en-us/powershell/azure/active-directory/overview?view=azureadps-1.0) module.) Regardless, a Partner Center account is not required for this script.

# Resources
Thanks to the following for helping me piece this together:
* https://lolware.net/blog/using-azure-mfa-onprem-ad/
* https://www.cyberdrain.com/automating-with-powershell-sending-mfa-push-messages-to-users/
