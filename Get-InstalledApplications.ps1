<#
.SYNOPSIS
    Script to Inventory User and Device Based Installed software on client machines

.PRE-REQUISITES
    -Service Account (or user account) in Application Workspace to perform actions
    -Azure App Registration with API permissions to read log analytics data
    -Client Secret for Azure App Registration

.DESCRIPTION
    This script will inventory the registry of devices it is associated with and publish the data that it finds in a Log Analytics table.
    This script will also create a json file for each application that is installed in c:\ProgramData\InstalledApps, in case you want to use this for anything else
    You will need to replace out the values listed below.
        ClientID - You will need an app registration with the correct permissions to read Log Analytics data
        ClientSecret - You will need to generate a client secret for that new app registration
        TenantID - Enter this so that we can query the correct tenant
        WorkspaceID - Enter the workspace ID for the Log Analytics workspace you are connecting to
        SharedKey - Enter the Log Analytics Primary Key 

.EXAMPLE
    .\\Get-InstalledApplications.ps1

#>
# Function to retrieve user-based installed applications
function Get-UserBasedApplications {
    $userSIDs = Get-ChildItem -Path "Registry::HKEY_USERS" | Where-Object { $_.Name -notmatch "_Classes$" }
    $applications = @()

    foreach ($userSID in $userSIDs) {
        $userName = $($userSID.Name).substring(11)
        $userRegistryPath = "Registry::HKEY_USERS\$userName\Software\Microsoft\Windows\CurrentVersion\Uninstall"

        if (Test-Path -Path $userRegistryPath) {
            $keys = Get-ChildItem -Path $userRegistryPath -Recurse -ErrorAction SilentlyContinue
            foreach ($key in $keys) {
                $app = New-Object PSObject -Property @{
                    Name        = $key.GetValue("DisplayName", $null)
                    Version     = $key.GetValue("DisplayVersion", $null)
                    Publisher   = $key.GetValue("Publisher", $null)
                    InstallDate = $key.GetValue("InstallDate", $null)
                    InstallType = "User"
                    DeviceName  = $env:COMPUTERNAME
                }
                if ($app.Name) {
                    $applications += $app
                }
            }
        }
    }
    return $applications
}

# Function to retrieve machine-wide installed applications
function Get-MachineBasedApplications {
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    $applications = @()

    foreach ($path in $registryPaths) {
        $keys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
        foreach ($key in $keys) {
            $app = New-Object PSObject -Property @{
                Name        = $key.GetValue("DisplayName", $null)
                Version     = $key.GetValue("DisplayVersion", $null)
                Publisher   = $key.GetValue("Publisher", $null)
                InstallDate = $key.GetValue("InstallDate", $null)
                InstallType = "Device"
                DeviceName  = $env:COMPUTERNAME
            }
            if ($app.Name) {
                $applications += $app
            }
        }
    }
    return $applications
}

# Normalize application names
function Normalize-Name {
    param ([string]$Name)
    $normalized = $Name.Trim() -replace "^(Microsoft|Adobe|Google)\s+", "" -replace "\s+\(.*\)$", ""
    $normalized = $normalized -replace "[^a-zA-Z0-9\s]", ""
    return $normalized
}

# Normalize version strings
function Normalize-Version {
    param ([string]$Version)
    if ([System.Version]::TryParse($Version, [ref]$null)) {
        return $Version
    } elseif ($Version -match "(\d+(\.\d+)+)") {
        return $matches[1]
    } else {
        return "0.0.0.0"
    }
}

# Generate deterministic GUID
function Generate-DeterministicGUID {
    param ([string]$Name, [string]$Publisher)
    $inputString = "$Name|$Publisher"
    $hash = [System.Security.Cryptography.HashAlgorithm]::Create("MD5")
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($inputString)
    $hashBytes = $hash.ComputeHash($bytes)
    $guid = [guid]::New([System.BitConverter]::ToString($hashBytes).Replace("-", "").Substring(0, 32))
    return $guid.Guid
}

# Retrieve existing Log Analytics data
function Get-LogAnalyticsData {
    param ([string]$workspaceId, [string]$sharedKey, [string]$logType)
    $computerName = $env:COMPUTERNAME
    $query = @"
    DeviceInstalledApplications_CL
    | where DeviceName_s == '$computerName'
    | project GUID_g, NormalizedName_s, NormalizedVersion_s, DeviceName_s
"@
    $date = (Get-Date).ToUniversalTime().ToString("r")
    $contentLength = $query.Length
    $signatureString = "POST`n$contentLength`napplication/json`nx-ms-date:$date`n/api/query"
    $decodedKey = [Convert]::FromBase64String($sharedKey)
    $hmacsha256 = New-Object System.Security.Cryptography.HMACSHA256
    $hmacsha256.Key = $decodedKey
    $signatureBytes = $hmacsha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($signatureString))
    $encodedSignature = [Convert]::ToBase64String($signatureBytes)
    $headers = @{
        "Authorization" = "SharedKey ${workspaceId}:$encodedSignature"
        "Content-Type"  = "application/json"
        "x-ms-date"     = $date
    }
    $uri = "https://$workspaceId.ods.opinsights.azure.com/api/query?api-version=2016-04-01"
    $response = Invoke-RestMethod -Uri $uri -Method Post -Body $query -Headers $headers
    return $response | ConvertFrom-Json
}

function Get-Token {
    $BearerBody = @{
        "grant_type" = "client_credentials"
        "client_id" = $ClientID
        "client_secret" = $ClientSecret
        "resource" = "https://api.loganalytics.io/"
    }

    # Get a bearer token for future requests
    $response = Invoke-WebRequest -Uri "https://login.microsoftonline.com/$tenantID/oauth2/token" -Method Post -ContentType "application/x-www-form-urlencoded" -Body $BearerBody
    $responsebody = $response.Content
    $responseobject = $responsebody | ConvertFrom-Json
    $bearerToken = $responseobject.access_token
    return $bearerToken
}

Function Get-DataFromAPI {
    $bearerToken = Get-Token
    $formattedResults = @()
    $headers = @{
        "Authorization" = "Bearer $bearerToken"
        "Content-Type" = "application/json"
    }
    $KQLquery = "DeviceInstalledApps_CL 
| where DeviceName_s == '$env:COMPUTERNAME'
| project GUID_g, NormalizedName_s, NormalizedVersion_s, DeviceName_s, Publisher_s "

    $body = @{
        query = $KQLquery
    } | ConvertTo-Json -Depth 10

    $response = Invoke-RestMethod -Uri $endpoint -Method Post -Headers $headers -Body $body

    # Process the response to map rows to column names
    if ($response) {
        $columns = $response.tables[0].columns
        $rows = $response.tables[0].rows

        foreach ($row in $rows) {
            # Create a PSCustomObject for each row
            $rowObject = [PSCustomObject]@{}
            for ($i = 0; $i -lt $columns.Count; $i++) {
                $columnName = $columns[$i].name
                $rowObject | Add-Member -MemberType NoteProperty -Name $columnName -Value $row[$i]
            }

            # Add the formatted row to the results list
            $formattedResults += $rowObject
        }

        #Write-Host "Query Successful! Results processed." -ForegroundColor Green
    } else {
        Write-Host "Query Failed!" -ForegroundColor Red
    }
    
    return $formattedResults
}

# Send data to Log Analytics
function Send-ToLogAnalytics {
    param ([string]$workspaceId, [string]$sharedKey, [string]$logType, [string]$jsonData)
    
    $date = (Get-Date).ToUniversalTime().ToString("r")
    $contentLength = $jsonData.Length
    $signatureString = "POST`n$contentLength`napplication/json`nx-ms-date:$date`n/api/logs"
    $decodedKey = [Convert]::FromBase64String($sharedKey)
    $hmacsha256 = New-Object System.Security.Cryptography.HMACSHA256
    $hmacsha256.Key = $decodedKey
    $signatureBytes = $hmacsha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($signatureString))
    $encodedSignature = [Convert]::ToBase64String($signatureBytes)
    $signature = "SharedKey ${WorkspaceId}:$encodedSignature"

    $headers = @{
        "Authorization" = "$signature"
        "Content-Type"  = "application/json"
        "x-ms-date"     = $date
        "Log-Type"      = $logType
    }
    $uri = "https://$workspaceId.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    
    Write-Host $jsonData
    Write-Host "URI: $uri"
    Write-Host "Headers: $(ConvertTo-Json $headers -Depth 10)"
    try {
        $response = Invoke-WebRequest -Uri $uri -Method Post -Body $jsonData -Headers $headers -Verbose
        Write-Host "Status Code: $($response.StatusCode)"
        Write-Host "Response Body: $($response.Content)"
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Assign Log Analytics details
$ClientID = "clientID" # Replace this with your own
$ClientSecret = "clientSecretValue" # Replace this with your own
$TenantID = "tenantID" # Replace this with your own
$workspaceId = "workspaceID" # Replace this with your own
$sharedKey = "workspacePrimaryKey" # Replace this with your own
$logType = "DeviceInstalledApps"
$endpoint = "https://api.loganalytics.io/v1/workspaces/$workspaceId/query"

# Define folder path for local files
$folderPath = "C:\ProgramData\InstalledApps"
if (!(Test-Path -Path $folderPath)) {
    New-Item -ItemType Directory -Path $folderPath
}

# Collect applications
$userApps = Get-UserBasedApplications
$machineApps = Get-MachineBasedApplications
$allApplications = $userApps + $machineApps

# Normalize and process applications
foreach ($app in $allApplications) {
    $app | Add-Member -NotePropertyName NormalizedName -NotePropertyValue (Normalize-Name -Name $app.Name)
    $app | Add-Member -NotePropertyName NormalizedVersion -NotePropertyValue (Normalize-Version -Version $app.Version)
    $app | Add-Member -NotePropertyName GUID -NotePropertyValue (Generate-DeterministicGUID -Name $app.NormalizedName -Publisher $app.Publisher)
    $app | Add-Member -NotePropertyName IsDeleted -NotePropertyValue $false
    $app | Add-Member -NotePropertyName LastUpdated -NotePropertyValue (Get-Date).ToUniversalTime().ToString("o")
}

# Retrieve existing data
Try {
    $existingData = Get-DataFromAPI
} catch {
    $existingData = $null
}

# Organize data
$localAppsHash = @{}
foreach ($app in $allApplications) { $localAppsHash[$app.GUID] = $app }


    $existingAppsHash = @{}
    foreach ($app in $existingData) { $existingAppsHash[$app.GUID_g] = $app }


# Identify changes
$adds = @()
$updates = @()
$deletes = @()

foreach ($guid in $localAppsHash.Keys) {
    if (-not $existingAppsHash.ContainsKey($guid)) {
        $adds += $localAppsHash[$guid]
    } else {
        $localApp = $localAppsHash[$guid]
        $existingApp = $existingAppsHash[$guid]
        if ($localApp.NormalizedVersion -ne $existingApp.NormalizedVersion_s -or
            $localApp.Publisher -ne $existingApp.Publisher_s) {
            $updates += $localApp
        }
    }
}
If ($existingAppsHash) {
    foreach ($guid in $existingAppsHash.Keys) {
        if (-not $localAppsHash.ContainsKey($guid)) {
            $deletes += $existingAppsHash[$guid]
        }
    }
}

# Handle adds
if ($adds.Count -gt 0) {
    foreach ($add in $adds) {
        $fileName = "$($add.GUID).json"
        $filePath = Join-Path -Path $folderPath -ChildPath $fileName
        $addJson = $add | ConvertTo-Json -Depth 3
        Set-Content -Path $filePath -Value $addJson -Encoding UTF8
    }
    $addsJson = $adds | ConvertTo-Json -Depth 10
    Send-ToLogAnalytics -workspaceId $workspaceId -sharedKey $sharedKey -logType $logType -jsonData $addsJson
}

# Handle updates
if ($updates.Count -gt 0) {
    foreach ($update in $updates) {
        $update.IsDeleted = $false
        $update.LastUpdated = (Get-Date).ToUniversalTime().ToString("o")
        $fileName = "$($update.GUID).json"
        $filePath = Join-Path -Path $folderPath -ChildPath $fileName
        $updateJson = $update | ConvertTo-Json -Depth 3
        Set-Content -Path $filePath -Value $updateJson -Encoding UTF8
    }
    $updatesJson = $updates | ConvertTo-Json -Depth 3
    Send-ToLogAnalytics -workspaceId $workspaceId -sharedKey $sharedKey -logType $logType -jsonData $updatesJson
}

# Handle deletions
if ($deletes.Count -gt 0) {
    foreach ($delete in $deletes) {
        $delete.IsDeleted = $true
        $delete.LastUpdated = (Get-Date).ToUniversalTime().ToString("o")
        $fileName = "$($delete.GUID).json"
        $filePath = Join-Path -Path $folderPath -ChildPath $fileName
        if (Test-Path -Path $filePath) {
            Remove-Item -Path $filePath -Force
        }
    }
    $deletesJson = $deletes | ConvertTo-Json -Depth 3
    Send-ToLogAnalytics -workspaceId $workspaceId -sharedKey $sharedKey -logType $logType -jsonData $deletesJson
}
