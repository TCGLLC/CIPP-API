function Get-CIPPEXODelegates {
    [CmdletBinding()]
    param (
        $TenantFilter,
        $APIName = 'Get Delegate Permissions List'
    )
	
	$result = @()

    try {    
        Write-Host 'Fetching Mailboxes.'
        $Mailboxes = New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-Mailbox' 

		foreach ($mb in $mailboxes) {
            try {
		        Write-Host "Processing  $($mb.UserPrincipalName)"
			    $mailboxObj = [PSCustomObject]@{
				    UPN                 = $mb.UserPrincipalName
				    PrimarySmtpAddress  = $mb.PrimarySmtpAddress
				    Permissions         = @()
			    }
			
			    $fullAccessRaw = New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-MailboxPermission' -cmdParams @{Identity = $mb.Identity } -Anchor $mb.Identity

			    $fullAccess = $fullAccessRaw | Where-Object {
				    $_.User -and $_.User.ToString() -notlike "NT AUTHORITY\SELF"
			    }
			    foreach ($perm in $fullAccess) {
				    $mailboxObj.Permissions += [PSCustomObject]@{
					    Delegate     = $perm.User.ToString()
					    AccessRights = ($perm.AccessRights -join ", ")
				    }
			    }

			    if ($mb.GrantSendOnBehalfTo) {
				    foreach ($delegate in $mb.GrantSendOnBehalfTo) {
					    $mailboxObj.Permissions += [PSCustomObject]@{
						    Delegate     = $delegate.ToString()
						    AccessRights = "SendOnBehalf"
					    }
				    }
			    }
                if($mailboxObj.Permissions.Count -eq 0) {
                    
                } else { 
                    $jsonPermissions = $mailboxObj.Permissions | ConvertTo-Json
                    Write-Host "Finished processing $($mb.UserPrincipalName) as $jsonPermissions"
			        $result += $mailboxObj
                }
            } catch {
                Write-Host "Failed to process mailbox data: $($mb.UserPrincipalName)"
            }
		}
           
		# Convert the final result to JSON and output it
		$returnResult = $result | ConvertTo-Json -Depth 5
        Write-Host "Result: $returnResult"
        return $returnResult
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        Write-Host "Result: $ErrorMessage"
        return "Error in JW's custom function. "
    }
}