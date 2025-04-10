<# 
.SYNOPSIS
    Reports module for CSP Reporting solution.
.DESCRIPTION
    This module provides functions for generating various reports from Microsoft Graph API
    including MFA status, audit logs, directory information, and usage reports.
.NOTES
    File Name      : Reports.psm1
    Prerequisite   : PowerShell Core 7.0 or later
                     Microsoft Graph PowerShell SDK
                     Auth.psm1 module
#>

#region Helper Functions
function Export-CSPReportData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSObject[]]$Data,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        [Parameter(Mandatory = $true)]
        [string]$FileName,
        [Parameter(Mandatory = $true)]
        [ValidateSet("CSV", "JSON", "Both")]
        [string]$OutputFormat
    )
    try {
        if (-not (Test-Path -Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        switch ($OutputFormat) {
            "CSV" {
                $csvPath = Join-Path -Path $OutputPath -ChildPath "$FileName.csv"
                $Data | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            }
            "JSON" {
                $jsonPath = Join-Path -Path $OutputPath -ChildPath "$FileName.json"
                $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
            }
            "Both" {
                $csvPath = Join-Path -Path $OutputPath -ChildPath "$FileName.csv"
                $Data | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                $jsonPath = Join-Path -Path $OutputPath -ChildPath "$FileName.json"
                $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
            }
        }
        return $true
    } catch {
        Write-Error "Error in Export-CSPReportData: $_"
        return $false
    }
}

function Format-CSPReportFileName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ReportType,
        [Parameter(Mandatory = $true)]
        [string]$TenantName
    )
    try {
        $dateStamp = Get-Date -Format "yyyyMMdd"
        return "${ReportType}_${TenantName}_${dateStamp}"
    } catch {
        Write-Error "Error in Format-CSPReportFileName: $_"
        return "Error_${ReportType}_${TenantName}"
    }
}
#endregion

#region Public Functions
function Get-CSPMFAReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        [Parameter(Mandatory = $true)]
        [string]$TenantName,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        [Parameter(Mandatory = $false)]
        [ValidateSet("CSV", "JSON", "Both")]
        [string]$OutputFormat = "CSV",
        [Parameter(Mandatory = $false)]
        [bool]$IncludeDisabledUsers = $false,
        [Parameter(Mandatory = $false)]
        [bool]$IncludeGuestUsers = $true,
        [Parameter(Mandatory = $false)]
        [string]$StatePath,
        [Parameter(Mandatory = $false)]
        [int]$BatchSize = 50,
        [Parameter(Mandatory = $false)]
        [switch]$Resume
    )
    try {
        Write-CSPLog -Message "Generating MFA report for tenant $TenantName" -Level "INFO"

        # Initialize state
        $stateParams = @{}
        if ($StatePath) { $stateParams.StatePath = $StatePath }
        $state = Initialize-CSPProcessState @stateParams

        $skipToUserId = $null
        $processedCount = 0
        if ($Resume -and $state.ResumedFromSave) {
            Write-CSPLog -Message "Resuming MFA report generation from previous state" -Level "INFO"
            $reportState = Get-CSPProcessState -TenantId $TenantId -ReportType "MFA"
            if ($reportState -and $reportState.Data.LastProcessedUserId) {
                $skipToUserId = $reportState.Data.LastProcessedUserId
                $processedCount = $reportState.Data.ProcessedCount
                Write-CSPLog -Message "Resuming from user after ID: $skipToUserId (Already processed: $processedCount users)" -Level "INFO"
            }
            $mfaReportFilePath = Join-Path -Path $OutputPath -ChildPath "$(Format-CSPReportFileName -ReportType "MFA" -TenantName $TenantName).csv"
            if (Test-Path $mfaReportFilePath) {
                $mfaReport = @(Import-Csv -Path $mfaReportFilePath)
            } else {
                $mfaReport = @()
            }
        } else {
            $mfaReport = @()
        }

        # Build filter
        $filter = $null
        if (-not $IncludeDisabledUsers) { $filter = "accountEnabled eq true" }
        if (-not $IncludeGuestUsers) {
            if ($filter) { $filter += " and userType eq 'Member'" }
            else { $filter = "userType eq 'Member'" }
        }

        # Get user count
        $query = @()
        $query += '$count=true'
        $query += '$top=1'
        if ($filter) { $query += '$filter=' + [System.Web.HttpUtility]::UrlEncode($filter) }
        $userCountUrl = "https://graph.microsoft.com/v1.0/users?" + ($query -join "&")
        Write-CSPLog -Message "User count request URL: $userCountUrl" -Level "DEBUG"

        $userCount = Invoke-CSPWithRetry -ScriptBlock {
            $headers = @{ "ConsistencyLevel" = "eventual" }
            $response = Invoke-MgGraphRequest -Method GET -Uri $userCountUrl -Headers $headers
            $response.'@odata.count'
        } -ActivityName "Get user count" -MaxRetries 3

        Write-CSPLog -Message "Found $userCount users in tenant $TenantName" -Level "INFO"
        if ($userCount -eq 0) {
            Write-CSPLog -Message "No users found, skipping MFA report." -Level "WARNING"
            return @()
        }

        # Initialize paging
        $foundSkipUser = $skipToUserId -eq $null
        $skipToUserIdFound = $false
        $lastProcessedUserId = $null
        $processedTotal = $processedCount

        $query = @()
        $query += '$top=' + $BatchSize
        if ($filter) { $query += '$filter=' + [System.Web.HttpUtility]::UrlEncode($filter) }
        $nextLink = "https://graph.microsoft.com/v1.0/users?" + ($query -join "&")

        do {
            Write-CSPProgress -Activity "Retrieving users from tenant $TenantName" -Status "Processed $processedTotal of $userCount users" -PercentComplete ([Math]::Min((($processedTotal / $userCount) * 100), 100)) -TenantId $TenantId -ReportType "MFA"

            $userResponse = Invoke-CSPWithRetry -ScriptBlock {
                Invoke-MgGraphRequest -Method GET -Uri $nextLink -Headers @{ "ConsistencyLevel" = "eventual" }
            } -ActivityName "Get user batch" -MaxRetries 3

            $userBatch = $userResponse.value

            if (-not $userBatch -or $userBatch.Count -eq 0) {
                Write-CSPLog -Message "No more users to process" -Level "INFO"
                break
            }

            $batchIndex = 0
            foreach ($user in $userBatch) {
                $batchIndex++
                $processedTotal++

                if (-not $foundSkipUser) {
                    if ($user.Id -eq $skipToUserId) {
                        $skipToUserIdFound = $true
                        $foundSkipUser = $true
                        Write-CSPLog -Message "Found resumption point user with ID: $skipToUserId" -Level "INFO"
                    }
                    continue
                }

                $percentComplete = [Math]::Min((($processedTotal / $userCount) * 100), 100)
                $statusMessage = "User $processedTotal of $userCount - $($user.UserPrincipalName)"
                Write-CSPProgress -Activity "Processing MFA status" -Status $statusMessage -PercentComplete $percentComplete -TenantId $TenantId -ReportType "MFA"

                try {
                    $authMethods = Invoke-CSPWithRetry -ScriptBlock {
                        Get-MgUserAuthenticationMethod -UserId $user.Id
                    } -ActivityName "Get authentication methods" -MaxRetries 3

                    $mfaEnabled = $false
                    $mfaMethods = @()

                    foreach ($method in $authMethods) {
                        if ($method.AdditionalProperties -and $method.AdditionalProperties.ContainsKey("@odata.type")) {
                            $methodType = $method.AdditionalProperties["@odata.type"]
                            switch -Wildcard ($methodType) {
                                "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" {
                                    $mfaEnabled = $true
                                    $mfaMethods += "Microsoft Authenticator"
                                }
                                "#microsoft.graph.phoneAuthenticationMethod" {
                                    $mfaEnabled = $true
                                    $mfaMethods += "Phone"
                                }
                                "#microsoft.graph.fido2AuthenticationMethod" {
                                    $mfaEnabled = $true
                                    $mfaMethods += "FIDO2 Security Key"
                                }
                                "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" {
                                    $mfaEnabled = $true
                                    $mfaMethods += "Windows Hello for Business"
                                }
                                "#microsoft.graph.softwareOathAuthenticationMethod" {
                                    $mfaEnabled = $true
                                    $mfaMethods += "Software OATH Token"
                                }
                                "#microsoft.graph.*AuthenticationMethod" {
                                    $mfaEnabled = $true
                                    $methodName = $methodType -replace '#microsoft\.graph\.', '' -replace 'AuthenticationMethod', ''
                                    $mfaMethods += $methodName
                                }
                            }
                        }
                    }

                    $reportEntry = [PSCustomObject]@{
                        TenantName = $TenantName
                        UserId = $user.Id
                        DisplayName = $user.DisplayName
                        UserPrincipalName = $user.UserPrincipalName
                        AccountEnabled = $user.AccountEnabled
                        UserType = $user.UserType
                        MFAEnabled = $mfaEnabled
                        MFAMethods = if ($mfaMethods.Count -gt 0) { $mfaMethods -join ", " } else { "None" }
                        ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                    $mfaReport += $reportEntry
                } catch {
                    Write-CSPLog -Message "Error processing user $($user.UserPrincipalName): $($_.Exception.Message)" -Level "WARNING"
                    $reportEntry = [PSCustomObject]@{
                        TenantName = $TenantName
                        UserId = $user.Id
                        DisplayName = $user.DisplayName
                        UserPrincipalName = $user.UserPrincipalName
                        AccountEnabled = $user.AccountEnabled
                        UserType = $user.UserType
                        MFAEnabled = "Error"
                        MFAMethods = "Error: $($_.Exception.Message)"
                        ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                    $mfaReport += $reportEntry
                }

                $lastProcessedUserId = $user.Id

                if ($processedTotal % 10 -eq 0 -or $batchIndex -eq $userBatch.Count) {
                    if ($StatePath) {
                        $fileName = Format-CSPReportFileName -ReportType "MFA" -TenantName $TenantName
                        Export-CSPReportData -Data $mfaReport -OutputPath $OutputPath -FileName $fileName -OutputFormat $OutputFormat
                    }
                    Update-CSPProcessState -TenantId $TenantId -TenantName $TenantName -ReportType "MFA" -Status "InProgress" -Data @{
                        LastProcessedUserId = $lastProcessedUserId
                        ProcessedCount = $processedTotal
                        TotalUsers = $userCount
                        PercentComplete = $percentComplete
                    }
                }
            }

            $nextLink = $userResponse.'@odata.nextLink'

        } while ($nextLink)

        Write-CSPProgress -Activity "Processing MFA status" -Status "Completed" -PercentComplete 100 -Completed -TenantId $TenantId -ReportType "MFA"

        $fileName = Format-CSPReportFileName -ReportType "MFA" -TenantName $TenantName
        Export-CSPReportData -Data $mfaReport -OutputPath $OutputPath -FileName $fileName -OutputFormat $OutputFormat

        Update-CSPProcessState -TenantId $TenantId -TenantName $TenantName -ReportType "MFA" -Status "Completed" -Data @{
            LastProcessedUserId = $lastProcessedUserId
            ProcessedCount = $processedTotal
            TotalUsers = $userCount
            PercentComplete = 100
        }

        Write-CSPLog -Message "MFA report for tenant $TenantName completed. Processed $processedTotal of $userCount users." -Level "INFO"
        return $mfaReport
    } catch {
        Write-CSPLog -Message "Error generating MFA report for tenant `${TenantName}`: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}
#endregion