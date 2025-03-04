function Get-CIPPEXODelegates {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        
        [string]$APIName = 'Get Delegate Permissions List'
    )
    
    # Retrieve the table and overall cached entity
    $Table = Get-CIPPTable -TableName CachedDelegateAccess
    $cacheFilter = "PartitionKey eq '$TenantFilter' and RowKey eq 'CachedResult'"
    $CachedEntity = Get-CIPPAzDataTableEntity @Table -Filter $cacheFilter
    $currentTime = [DateTimeOffset]::UtcNow
    $cacheUpdateNeeded = $false

    # Check if overall cache exists and is recent (< 2 hours)
    if ($CachedEntity -ne $null -and $CachedEntity.FinishTimestamp) {
        $cacheFinishTime = [DateTimeOffset]$CachedEntity.FinishTimestamp
        if (($currentTime - $cacheFinishTime).TotalHours -ge 2) {
            Write-Verbose "Overall cache is older than 2 hours. Update needed."
            $cacheUpdateNeeded = $true
        }
    }
    else {
        $cacheUpdateNeeded = $true
    }
    
    # Helper function: Processes all mailboxes and returns a results array
    function Process-Mailboxes {
        $result = @()
        Write-Host 'Fetching Mailboxes.'
        $Mailboxes = New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-Mailbox'
    
        foreach ($mb in $Mailboxes) {
            try {
                Write-Host "Processing $($mb.UserPrincipalName)"
                $mailboxObj = [PSCustomObject]@{
                    UPN                = $mb.UserPrincipalName
                    PrimarySmtpAddress = $mb.PrimarySmtpAddress
                    Permissions        = @()
                }
    
                # Check for a cached mailbox entry
                $userFilter = "PartitionKey eq '$TenantFilter' and RowKey eq '$($mb.UserPrincipalName)'"
                $UserData = Get-CIPPAzDataTableEntity @Table -Filter $userFilter
                if ($UserData -ne $null -and $UserData.FinishTimestamp) {
                    $userFinishTime = [DateTimeOffset]$UserData.FinishTimestamp
                    if (($currentTime - $userFinishTime).TotalHours -lt 2) {
                        # Use cached data if still valid
                        $cachedMailbox = $UserData.Data | ConvertFrom-Json
                        if($cachedMailbox.Permissions.Count -gt 0) {
                            $result += $cachedMailbox
                        }
                        continue
                    }
                }
    
                # Retrieve full access permissions
                $fullAccessRaw = New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-MailboxPermission' -cmdParams @{Identity = $mb.Identity} -Anchor $mb.Identity
                $fullAccess = $fullAccessRaw | Where-Object {
                    $_.User -and $_.User.ToString() -notlike "NT AUTHORITY\SELF"
                }
                foreach ($perm in $fullAccess) {
                    $mailboxObj.Permissions += [PSCustomObject]@{
                        Delegate     = $perm.User.ToString()
                        AccessRights = ($perm.AccessRights -join ", ")
                    }
                }
    
                # Retrieve send-on-behalf permissions if available
                if ($mb.GrantSendOnBehalfTo) {
                    foreach ($delegate in $mb.GrantSendOnBehalfTo) {
                        $mailboxObj.Permissions += [PSCustomObject]@{
                            Delegate     = $delegate.ToString()
                            AccessRights = "SendOnBehalf"
                        }
                    }
                }
    
                # Cache individual mailbox result
                $userCacheEntity = @{
                    PartitionKey    = "$TenantFilter"
                    RowKey          = "$($mb.UserPrincipalName)"
                    FinishTimestamp = [DateTimeOffset]::UtcNow
                    Data            = [string](ConvertTo-Json -InputObject $mailboxObj -Depth 10 -Compress)
                }
                Add-CIPPAzDataTableEntity @Table -Entity $userCacheEntity -Force
    
                if ($mailboxObj.Permissions.Count -gt 0) {
                    $jsonPermissions = $mailboxObj.Permissions | ConvertTo-Json
                    Write-Host "Finished processing $($mb.UserPrincipalName) as $jsonPermissions"
                    $result += $mailboxObj
                }
            }
            catch {
                Write-Host "Failed to process mailbox data: $($mb.UserPrincipalName)"
            }
        }
        return $result
    }
    
    # If cache update is needed, process mailboxes, update overall cache, and return fresh data.
    if ($cacheUpdateNeeded) {
        try {
            $result = Process-Mailboxes
            $returnResult = $result | ConvertTo-Json -Depth 5
            Write-Host "Result: $returnResult"
            $cacheEntity = @{
                PartitionKey    = "$TenantFilter"
                RowKey          = "CachedResult"
                FinishTimestamp = [DateTimeOffset]::UtcNow
                Data            = [string](ConvertTo-Json -InputObject $result -Depth 10 -Compress)
            }
            Add-CIPPAzDataTableEntity @Table -Entity $cacheEntity -Force
            return $returnResult
        }
        catch {
            $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
            Write-Host "Result: $ErrorMessage"
            return "Error in JW's custom function. "
        }
    }
    else {
        # Return cached overall result if it's still fresh.
        return $CachedEntity.Data
    }
}