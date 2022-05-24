using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

$APIName = $TriggerMetadata.FunctionName
Log-Request -user $request.headers.'x-ms-client-principal' -API $APINAME  -message "Accessed this API" -Sev "Debug"


# Write to the Azure Functions log stream.
Write-Host "PowerShell HTTP trigger function processed a request."

# Interact with query parameters or the body of the request.
$TenantFilter = $Request.Query.TenantFilter
if ($TenantFilter -eq "AllTenants") { $Tenants = (Get-Tenants).DefaultDomainName } else { $tenants = $TenantFilter }

try {
        $GraphRequest = foreach ($Tenant in $Tenants) {
                try {
                        $ServicePrincipals = New-GraphGetRequest -uri "https://graph.microsoft.com/beta/servicePrincipals?`$select=id,displayName" -tenantid $Tenant
                        New-GraphGetRequest -uri "https://graph.microsoft.com/beta/oauth2PermissionGrants" -tenantid $Tenant | ForEach-Object {
                                [PSCustomObject]@{
                                        Tenant    = $Tenant
                                        Name      = ($ServicePrincipals | Where-Object -Property id -EQ $_.clientId).displayName
                                        ID        = $_.clientId
                                        Scope     = ($_.scope -join ',')
                                        StartTime = $_.startTime
                                }
                        }
                        $StatusCode = [HttpStatusCode]::OK
                }
                catch {
                        continue
                }
        }
}
catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        $StatusCode = [HttpStatusCode]::Forbidden
        $GraphRequest = $ErrorMessage
}

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = $StatusCode
                Body       = @($GraphRequest)
        })
