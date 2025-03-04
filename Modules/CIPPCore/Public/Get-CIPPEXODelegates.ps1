function Get-CIPPEXODelegates {
    [CmdletBinding()]
    param (
        $TenantFilter,
        $APIName = 'Get Delegate Permissions List'
    )
	
	$result = @()

	$Table = Get-CIPPTable -TableName CachedDelegateAccess
	$Data = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$TenantFilter' and RowKey eq 'CachedResult'"
    $currentTime = [DateTimeOffset]::UtcNow
    
    if ($Data -eq $null) {
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
            $Data = @{
				PartitionKey = "$TenantFilter"
				RowKey       = "CachedResult"
                FinishTimestamp = [DateTimeOffset]::UtcNow
				Data         = [string](ConvertTo-Json -InputObject $result -Depth 10 -Compress)
			}
            Add-CIPPAzDataTableEntity @Table -Entity $Data -Force
            return $returnResult
        } catch {
            $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
            Write-Host "Result: $ErrorMessage"
            return "Error in JW's custom function. "
        }
    } else {
        if($Data.FinishTimestamp) {
            $finishTime = [DateTimeOffset]$Data.FinishTimestamp
            $timeDiff = $currentTime - $finishTime
            if ($timeDiff.TotalHours -ge 2) {
                Write-Verbose "Cache entry is older than 2 hours. Update needed."
                $updateNeeded = $true
            }
       }
       if($updateNeeded) {
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
                    $Data = @{
				        PartitionKey = "$TenantFilter"
				        RowKey       = "CachedResult"
                        FinishTimestamp = [DateTimeOffset]::UtcNow
				        Data         = [string](ConvertTo-Json -InputObject $result -Depth 10 -Compress)
			        }
                    Add-CIPPAzDataTableEntity @Table -Entity $Data -Force
                    return $returnResult
                } catch {
                    $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
                    Write-Host "Result: $ErrorMessage"
                    return "Error in JW's custom function. "
                }
       } else {
            return $Data.Data
       }
    }
}