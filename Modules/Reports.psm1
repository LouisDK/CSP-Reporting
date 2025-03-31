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
    <#
    .SYNOPSIS
        Exports report data to the specified format.
    
    .DESCRIPTION
        Exports report data to CSV, JSON, or both formats.
    
    .PARAMETER Data
        The data to export.
    
    .PARAMETER OutputPath
        The path where the output file(s) will be saved.
    
    .PARAMETER FileName
        The base name of the output file(s) without extension.
    
    .PARAMETER OutputFormat
        The format(s) to export the data to. Valid values are "CSV", "JSON", or "Both".
    
    .EXAMPLE
        Export-CSPReportData -Data $mfaReport -OutputPath "C:\Reports" -FileName "MFAReport_Contoso" -OutputFormat "Both"
    #>
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
        # Create the output directory if it doesn't exist
        if (-not (Test-Path -Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        
        # Export based on the specified format
        switch ($OutputFormat) {
            "CSV" {
                $csvPath = Join-Path -Path $OutputPath -ChildPath "$FileName.csv"
                $Data | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                Write-Verbose "Exported data to CSV: $csvPath"
            }
            "JSON" {
                $jsonPath = Join-Path -Path $OutputPath -ChildPath "$FileName.json"
                $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
                Write-Verbose "Exported data to JSON: $jsonPath"
            }
            "Both" {
                $csvPath = Join-Path -Path $OutputPath -ChildPath "$FileName.csv"
                $Data | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                Write-Verbose "Exported data to CSV: $csvPath"
                
                $jsonPath = Join-Path -Path $OutputPath -ChildPath "$FileName.json"
                $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
                Write-Verbose "Exported data to JSON: $jsonPath"
            }
        }
        
        return $true
    }
    catch {
        Write-Error "Error in Export-CSPReportData: $_"
        return $false
    }
}

function Format-CSPReportFileName {
    <#
    .SYNOPSIS
        Formats a report file name with tenant name and date.
    
    .DESCRIPTION
        Formats a report file name with tenant name and date to ensure uniqueness.
    
    .PARAMETER ReportType
        The type of report.
    
    .PARAMETER TenantName
        The name of the tenant.
    
    .EXAMPLE
        Format-CSPReportFileName -ReportType "MFA" -TenantName "Contoso"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ReportType,
        
        [Parameter(Mandatory = $true)]
        [string]$TenantName
    )
    
    try {
        # Format the file name with tenant name and date
        $dateStamp = Get-Date -Format "yyyyMMdd"
        $fileName = "${ReportType}_${TenantName}_${dateStamp}"
        
        return $fileName
    }
    catch {
        Write-Error "Error in Format-CSPReportFileName: $_"
        return "Error_${ReportType}_${TenantName}"
    }
}
#endregion

#region Public Functions
function Get-CSPMFAReport {
    <#
    .SYNOPSIS
        Generates an MFA status report for a tenant.
    
    .DESCRIPTION
        Retrieves user information and MFA status from Microsoft Graph API
        and generates a report. Supports resumable operations and progress reporting.
    
    .PARAMETER TenantId
        The tenant ID (GUID) or domain name of the tenant.
    
    .PARAMETER TenantName
        The display name of the tenant for reporting purposes.
    
    .PARAMETER OutputPath
        The path where the report will be saved.
    
    .PARAMETER OutputFormat
        The format(s) to export the report to. Valid values are "CSV", "JSON", or "Both".
        
    .PARAMETER IncludeDisabledUsers
        Whether to include disabled users in the report. Default is false.
    
    .PARAMETER IncludeGuestUsers
        Whether to include guest users in the report. Default is true.
        
    .PARAMETER StatePath
        Path to a state file that will be used to track progress and enable resuming the operation.
        
    .PARAMETER BatchSize
        The number of users to process in each batch. Default is 50.
        
    .PARAMETER Resume
        If specified, attempts to resume from the previous state file.
    
    .EXAMPLE
        Get-CSPMFAReport -TenantId "contoso.onmicrosoft.com" -TenantName "Contoso" -OutputPath "C:\Reports" -OutputFormat "CSV"
    
    .EXAMPLE
        Get-CSPMFAReport -TenantId "contoso.onmicrosoft.com" -TenantName "Contoso" -OutputPath "C:\Reports" -StatePath "C:\Temp\MFAReport_State.xml" -Resume
    #>
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
        
        # Initialize state for resumability and progress tracking
        $stateParams = @{}
        if ($StatePath) {
            $stateParams.StatePath = $StatePath
        }
        
        $state = Initialize-CSPProcessState @stateParams
        
        # If resume is specified and we successfully restored state
        $skipToUserId = $null
        $processedCount = 0
        if ($Resume -and $state.ResumedFromSave) {
            Write-CSPLog -Message "Resuming MFA report generation from previous state" -Level "INFO"
            
            # Get the last processed user
            $reportState = Get-CSPProcessState -TenantId $TenantId -ReportType "MFA"
            if ($reportState -and $reportState.Data -and $reportState.Data.LastProcessedUserId) {
                $skipToUserId = $reportState.Data.LastProcessedUserId
                $processedCount = $reportState.Data.ProcessedCount
                Write-CSPLog -Message "Resuming from user after ID: $skipToUserId (Already processed: $processedCount users)" -Level "INFO"
            }
            
            # Load existing report data if available
            $mfaReportFilePath = Join-Path -Path $OutputPath -ChildPath "$(Format-CSPReportFileName -ReportType "MFA" -TenantName $TenantName).csv"
            if (Test-Path $mfaReportFilePath) {
                Write-CSPLog -Message "Loading existing report data from $mfaReportFilePath" -Level "INFO"
                $mfaReport = @(Import-Csv -Path $mfaReportFilePath)
                Write-CSPLog -Message "Loaded $($mfaReport.Count) existing records" -Level "INFO"
            }
            else {
                $mfaReport = @()
            }
        }
        else {
            $mfaReport = @()
        }
        
        # Update the process state to indicate we're starting
        Update-CSPProcessState -TenantId $TenantId -TenantName $TenantName -ReportType "MFA" -Status "Started"
        
        # Check if connected to the correct tenant
        $connectionTest = Test-CSPConnection
        
        if (-not $connectionTest.Connected -or $connectionTest.TenantId -ne $TenantId) {
            throw "Not connected to the correct tenant. Please connect to tenant $TenantId first."
        }
        
        # Build the filter for users
        $filter = $null
        if (-not $IncludeDisabledUsers) {
            $filter = "accountEnabled eq true"
        }
        
        if (-not $IncludeGuestUsers) {
            if ($filter) {
                $filter += " and userType eq 'Member'"
            }
            else {
                $filter = "userType eq 'Member'"
            }
        }
        
        # Get total user count for progress reporting
        Write-CSPLog -Message "Retrieving user count from tenant $TenantName" -Level "INFO"
        $userCountParams = @{
            ConsistencyLevel = "eventual"
            Count = $true
        }
        if ($filter) {
            $userCountParams.Filter = $filter
        }
        
        $userCount = 0
        
        # Use retry logic for API calls
        $userCount = Invoke-CSPWithRetry -ScriptBlock {
            (Get-MgUser @userCountParams).Count
        } -ActivityName "Get user count" -MaxRetries 3
        
        Write-CSPLog -Message "Found $userCount users in tenant $TenantName" -Level "INFO"
        
        # Initialize a flag to keep track of whether we've found the user to skip to
        $foundSkipUser = $skipToUserId -eq $null
        $skipToUserIdFound = $false
        
        # Track the last processed user ID for resumability
        $lastProcessedUserId = $null
        
        # Process users in batches with pagination
        $currentSkip = 0
        $processedTotal = $processedCount
        
        while ($true) {
            # Prepare parameters for Get-MgUser
            $params = @{
                Top = $BatchSize
                Skip = $currentSkip
                Property = "Id", "DisplayName", "UserPrincipalName", "AccountEnabled", "UserType"
            }
            
            if ($filter) {
                $params.Filter = $filter
            }
            
            # Get a batch of users
            Write-CSPProgress -Activity "Retrieving users from tenant $TenantName" -Status "Batch $([Math]::Floor($currentSkip / $BatchSize) + 1) (Processed $processedTotal of $userCount users)" -PercentComplete (($processedTotal / $userCount) * 100) -TenantId $TenantId -ReportType "MFA"
            
            # Use retry logic for API calls
            $userBatch = Invoke-CSPWithRetry -ScriptBlock {
                Get-MgUser @params
            } -ActivityName "Get user batch" -MaxRetries 3
            
            # Check if we got any users
            if (-not $userBatch -or $userBatch.Count -eq 0) {
                Write-CSPLog -Message "No more users to process" -Level "INFO"
                break
            }
            
            # Process each user in the batch
            $batchIndex = 0
            foreach ($user in $userBatch) {
                $batchIndex++
                
                # Skip users if we're resuming and haven't found the skip-to user yet
                if (-not $foundSkipUser) {
                    if ($user.Id -eq $skipToUserId) {
                        $skipToUserIdFound = $true
                        $foundSkipUser = $true
                        Write-CSPLog -Message "Found resumption point user with ID: $skipToUserId" -Level "INFO"
                    }
                    continue
                }
                
                # Update progress
                $processedTotal++
                $percentComplete = ($processedTotal / $userCount) * 100
                $statusMessage = "User $processedTotal of $userCount - $($user.UserPrincipalName)"
                Write-CSPProgress -Activity "Processing MFA status" -Status $statusMessage -PercentComplete $percentComplete -TenantId $TenantId -ReportType "MFA"
                
                try {
                    # Get authentication methods with retry logic
                    $authMethods = Invoke-CSPWithRetry -ScriptBlock {
                        Get-MgUserAuthenticationMethod -UserId $user.Id
                    } -ActivityName "Get authentication methods" -MaxRetries 3
                    
                    # Determine MFA status
                    $mfaEnabled = $false
                    $mfaMethods = @()
                    
                    foreach ($method in $authMethods) {
                        # Check if AdditionalProperties and @odata.type exist
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
                                # Add a catch-all for any new methods Microsoft might add
                                "#microsoft.graph.*AuthenticationMethod" {
                                    $mfaEnabled = $true
                                    $methodName = $methodType -replace '#microsoft\.graph\.', '' -replace 'AuthenticationMethod', ''
                                    $mfaMethods += $methodName
                                }
                            }
                        }
                    }
                    
                    # Create report entry
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
                }
                catch {
                    Write-CSPLog -Message "Error processing user $($user.UserPrincipalName): $($_.Exception.Message)" -Level "WARNING"
                    
                    # Add user to report with error
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
                
                # Update the last processed user ID
                $lastProcessedUserId = $user.Id
                
                # Update state every 10 users for resumability
                if ($processedTotal % 10 -eq 0 -or $batchIndex -eq $userBatch.Count) {
                    # Export incremental report if state path is provided
                    if ($StatePath) {
                        $fileName = Format-CSPReportFileName -ReportType "MFA" -TenantName $TenantName
                        Export-CSPReportData -Data $mfaReport -OutputPath $OutputPath -FileName $fileName -OutputFormat $OutputFormat
                    }
                    
                    # Update process state
                    Update-CSPProcessState -TenantId $TenantId -TenantName $TenantName -ReportType "MFA" -Status "InProgress" -Data @{
                        LastProcessedUserId = $lastProcessedUserId
                        ProcessedCount = $processedTotal
                        TotalUsers = $userCount
                        PercentComplete = $percentComplete
                    }
                }
            }
            
            # Move to the next batch
            $currentSkip += $BatchSize
            
            # If we didn't find the skip-to user in this batch but we're looking for it, check if we've gone through the entire list
            if (-not $foundSkipUser -and -not $skipToUserIdFound -and $currentSkip -gt $userCount) {
                Write-CSPLog -Message "Could not find the user to resume from with ID: $skipToUserId. Starting from the beginning." -Level "WARNING"
                $foundSkipUser = $true
                $currentSkip = 0
            }
        }
        
        # Final progress update
        Write-CSPProgress -Activity "Processing MFA status" -Status "Completed" -PercentComplete 100 -Completed -TenantId $TenantId -ReportType "MFA"
        
        # Export the final report
        $fileName = Format-CSPReportFileName -ReportType "MFA" -TenantName $TenantName
        Export-CSPReportData -Data $mfaReport -OutputPath $OutputPath -FileName $fileName -OutputFormat $OutputFormat
        
        # Update process state to completed
        Update-CSPProcessState -TenantId $TenantId -TenantName $TenantName -ReportType "MFA" -Status "Completed" -Data @{
            LastProcessedUserId = $lastProcessedUserId
            ProcessedCount = $processedTotal
            TotalUsers = $userCount
            PercentComplete = 100
        }
        
        Write-CSPLog -Message "MFA report for tenant $TenantName completed. Processed $processedTotal of $userCount users." -Level "INFO"
        return $mfaReport
    }
    catch {
        Write-CSPLog -Message "Error in Get-CSPMFAReport: $($_.Exception.Message)" -Level "ERROR"
        
        # Update process state to failed
        if ($TenantId -and $TenantName) {
            Update-CSPProcessState -TenantId $TenantId -TenantName $TenantName -ReportType "MFA" -Status "Failed" -Data @{
                Error = $_.Exception.Message
                ProcessedCount = $processedTotal
                TotalUsers = $userCount
            }
        }
        
        return $null
    }
}

function Get-CSPAuditLogReport {
    <#
    .SYNOPSIS
        Generates an audit log report for a tenant.
    
    .DESCRIPTION
        Retrieves audit log data from Microsoft Graph API and generates a report.
        Supports pagination, progress reporting, and resumability.
    
    .PARAMETER TenantId
        The tenant ID (GUID) or domain name of the tenant.
    
    .PARAMETER TenantName
        The display name of the tenant for reporting purposes.
    
    .PARAMETER OutputPath
        The path where the report will be saved.
    
    .PARAMETER OutputFormat
        The format(s) to export the report to. Valid values are "CSV", "JSON", or "Both".
    
    .PARAMETER DaysBack
        The number of days back to retrieve audit logs for. Default is 30.
    
    .PARAMETER StatePath
        Path to a state file that will be used to track progress and enable resuming the operation.
        
    .PARAMETER BatchSize
        The number of audit logs to process in each batch. Default is 100.
        
    .PARAMETER Resume
        If specified, attempts to resume from the previous state file.
    
    .EXAMPLE
        Get-CSPAuditLogReport -TenantId "contoso.onmicrosoft.com" -TenantName "Contoso" -OutputPath "C:\Reports" -OutputFormat "CSV" -DaysBack 7
    
    .EXAMPLE
        Get-CSPAuditLogReport -TenantId "contoso.onmicrosoft.com" -TenantName "Contoso" -OutputPath "C:\Reports" -DaysBack 30 -StatePath "C:\Temp\AuditReport_State.xml" -Resume
    #>
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
        [int]$DaysBack = 30,
        
        [Parameter(Mandatory = $false)]
        [string]$StatePath,
        
        [Parameter(Mandatory = $false)]
        [int]$BatchSize = 100,
        
        [Parameter(Mandatory = $false)]
        [switch]$Resume
    )
    
    try {
        Write-CSPLog -Message "Generating audit log report for tenant $TenantName" -Level "INFO"
        
        # Initialize state for resumability and progress tracking
        $stateParams = @{}
        if ($StatePath) {
            $stateParams.StatePath = $StatePath
        }
        
        $state = Initialize-CSPProcessState @stateParams
        
        # If resume is specified and we successfully restored state
        $skipToTimestamp = $null
        $processedCount = 0
        $totalProcessed = 0
        
        if ($Resume -and $state.ResumedFromSave) {
            Write-CSPLog -Message "Resuming audit log report generation from previous state" -Level "INFO"
            
            # Get the last processed timestamp
            $reportState = Get-CSPProcessState -TenantId $TenantId -ReportType "AuditLog"
            if ($reportState -and $reportState.Data -and $reportState.Data.LastProcessedTimestamp) {
                $skipToTimestamp = [DateTime]::Parse($reportState.Data.LastProcessedTimestamp)
                $processedCount = $reportState.Data.ProcessedCount
                $totalProcessed = $processedCount
                Write-CSPLog -Message "Resuming from logs after timestamp: $skipToTimestamp (Already processed: $processedCount logs)" -Level "INFO"
            }
            
            # Load existing report data if available
            $auditReportFilePath = Join-Path -Path $OutputPath -ChildPath "$(Format-CSPReportFileName -ReportType "AuditLog" -TenantName $TenantName).csv"
            if (Test-Path $auditReportFilePath) {
                Write-CSPLog -Message "Loading existing report data from $auditReportFilePath" -Level "INFO"
                $auditReport = @(Import-Csv -Path $auditReportFilePath)
                Write-CSPLog -Message "Loaded $($auditReport.Count) existing records" -Level "INFO"
            }
            else {
                $auditReport = @()
            }
        }
        else {
            $auditReport = @()
        }
        
        # Update the process state to indicate we're starting
        Update-CSPProcessState -TenantId $TenantId -TenantName $TenantName -ReportType "AuditLog" -Status "Started"
        
        # Check if connected to the correct tenant
        $connectionTest = Test-CSPConnection
        
        if (-not $connectionTest.Connected -or $connectionTest.TenantId -ne $TenantId) {
            throw "Not connected to the correct tenant. Please connect to tenant $TenantId first."
        }
        
        # Calculate date range (with proper UTC handling)
        $endDate = [System.DateTime]::UtcNow
        $startDate = $endDate.AddDays(-$DaysBack)
        
        # Format dates for Graph API
        $startDateString = $startDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
        $endDateString = $endDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        Write-CSPLog -Message "Retrieving audit logs from $startDateString to $endDateString" -Level "INFO"
        
        # If skipping to a timestamp (resuming), adjust the filter
        if ($skipToTimestamp) {
            $skipToTimestampString = $skipToTimestamp.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            $filter = "activityDateTime gt $skipToTimestampString and activityDateTime le $endDateString"
        }
        else {
            $filter = "activityDateTime ge $startDateString and activityDateTime le $endDateString"
        }
        
        # The Graph API doesn't support counting audit logs directly, so we'll need to estimate
        # We'll use a conservative estimate to start with
        $estimatedTotal = 1000 # Default estimate
        
        # Process audit logs in batches with pagination
        $currentPage = 1
        $lastProcessedTimestamp = $null
        $hasMoreRecords = $true
        
        while ($hasMoreRecords) {
            Write-CSPProgress -Activity "Retrieving audit logs from tenant $TenantName" -Status "Page $currentPage (Processed $totalProcessed logs so far)" -PercentComplete -1 -TenantId $TenantId -ReportType "AuditLog"
            
            # Get a batch of audit logs with retry logic
            $batchParams = @{
                Filter = $filter
                Top = $BatchSize
            }
            
            $auditBatch = Invoke-CSPWithRetry -ScriptBlock {
                Get-MgAuditLogDirectoryAudit @batchParams
            } -ActivityName "Get audit logs batch" -MaxRetries 3
            
            # If we have logs in this batch
            if ($auditBatch -and $auditBatch.Count -gt 0) {
                $batchSize = $auditBatch.Count
                Write-CSPLog -Message "Retrieved $batchSize audit logs" -Level "INFO"
                
                # Process each log in this batch
                $batchCount = 0
                foreach ($log in $auditBatch) {
                    $batchCount++
                    $totalProcessed++
                    
                    # Create report entry
                    $reportEntry = [PSCustomObject]@{
                        TenantName = $TenantName
                        ActivityDateTime = $log.ActivityDateTime
                        ActivityDisplayName = $log.ActivityDisplayName
                        Category = $log.Category
                        CorrelationId = $log.CorrelationId
                        InitiatedBy = if ($log.InitiatedBy.User) { $log.InitiatedBy.User.UserPrincipalName } else { $log.InitiatedBy.App.DisplayName }
                        InitiatorType = if ($log.InitiatedBy.User) { "User" } else { "Application" }
                        Result = $log.Result
                        ResultReason = $log.ResultReason
                        LogId = $log.Id
                        ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                    
                    $auditReport += $reportEntry
                    
                    # Keep track of the latest timestamp for resumability
                    if ($log.ActivityDateTime -and (!$lastProcessedTimestamp -or $log.ActivityDateTime -gt $lastProcessedTimestamp)) {
                        $lastProcessedTimestamp = $log.ActivityDateTime
                    }
                    
                    # Update state periodically for resumability
                    if ($totalProcessed % 50 -eq 0 -or $batchCount -eq $batchSize) {
                        # Export incremental report if state path is provided
                        if ($StatePath) {
                            $fileName = Format-CSPReportFileName -ReportType "AuditLog" -TenantName $TenantName
                            Export-CSPReportData -Data $auditReport -OutputPath $OutputPath -FileName $fileName -OutputFormat $OutputFormat
                        }
                        
                        # Calculate progress percentage (based on estimated total)
                        $percentComplete = if ($estimatedTotal -gt 0) { 
                            [Math]::Min(($totalProcessed / $estimatedTotal) * 100, 99) 
                        } else { 
                            -1 
                        }
                        
                        # Update process state
                        Update-CSPProcessState -TenantId $TenantId -TenantName $TenantName -ReportType "AuditLog" -Status "InProgress" -Data @{
                            LastProcessedTimestamp = $lastProcessedTimestamp
                            ProcessedCount = $totalProcessed
                            CurrentPage = $currentPage
                            PercentComplete = $percentComplete
                        }
                        
                        # Show progress
                        Write-CSPProgress -Activity "Processing audit logs" -Status "Processed $totalProcessed logs" -PercentComplete $percentComplete -TenantId $TenantId -ReportType "AuditLog"
                    }
                }
                
                # Check if we need to get the next page of results
                # Look for the presence of an @odata.nextLink property in the response
                # This might not be directly accessible, so we infer it based on batch size
                if ($batchSize -lt $BatchSize) {
                    # If we got fewer records than requested, we're at the end
                    $hasMoreRecords = $false
                    Write-CSPLog -Message "Retrieved fewer records than batch size, assuming no more records" -Level "INFO"
                }
                else {
                    # Adjust the filter to get the next set of records
                    # We use the timestamp of the last record to create a new filter
                    if ($lastProcessedTimestamp) {
                        $lastTimestampString = $lastProcessedTimestamp.ToString("yyyy-MM-ddTHH:mm:ssZ")
                        $filter = "activityDateTime gt $lastTimestampString and activityDateTime le $endDateString"
                        $currentPage++
                        
                        # Adjust our estimate of total records based on what we've seen so far
                        if ($totalProcessed -gt $estimatedTotal * 0.9) {
                            $estimatedTotal = $totalProcessed * 1.2 # Increase by 20%
                            Write-CSPLog -Message "Adjusting estimated total to $estimatedTotal" -Level "INFO"
                        }
                    }
                    else {
                        $hasMoreRecords = $false
                        Write-CSPLog -Message "No timestamp found to paginate, stopping" -Level "WARNING"
                    }
                }
            }
            else {
                # No more records
                $hasMoreRecords = $false
                Write-CSPLog -Message "No records returned, ending pagination" -Level "INFO"
            }
        }
        
        # Final progress update
        Write-CSPProgress -Activity "Processing audit logs" -Status "Completed" -PercentComplete 100 -Completed -TenantId $TenantId -ReportType "AuditLog"
        
        # Export the final report
        $fileName = Format-CSPReportFileName -ReportType "AuditLog" -TenantName $TenantName
        Export-CSPReportData -Data $auditReport -OutputPath $OutputPath -FileName $fileName -OutputFormat $OutputFormat
        
        # Update process state to completed
        Update-CSPProcessState -TenantId $TenantId -TenantName $TenantName -ReportType "AuditLog" -Status "Completed" -Data @{
            LastProcessedTimestamp = $lastProcessedTimestamp
            ProcessedCount = $totalProcessed
            PercentComplete = 100
        }
        
        Write-CSPLog -Message "Audit log report for tenant $TenantName completed. Retrieved $totalProcessed audit log entries." -Level "INFO"
        return $auditReport
    }
    catch {
        Write-CSPLog -Message "Error in Get-CSPAuditLogReport: $($_.Exception.Message)" -Level "ERROR"
        
        # Update process state to failed
        if ($TenantId -and $TenantName) {
            Update-CSPProcessState -TenantId $TenantId -TenantName $TenantName -ReportType "AuditLog" -Status "Failed" -Data @{
                Error = $_.Exception.Message
                ProcessedCount = $totalProcessed
                LastProcessedTimestamp = $lastProcessedTimestamp
            }
        }
        
        return $null
    }
}

function Get-CSPDirectoryReport {
    <#
    .SYNOPSIS
        Generates a directory information report for a tenant.
    
    .DESCRIPTION
        Retrieves directory information from Microsoft Graph API and generates a report.
    
    .PARAMETER TenantId
        The tenant ID (GUID) or domain name of the tenant.
    
    .PARAMETER TenantName
        The display name of the tenant for reporting purposes.
    
    .PARAMETER OutputPath
        The path where the report will be saved.
    
    .PARAMETER OutputFormat
        The format(s) to export the report to. Valid values are "CSV", "JSON", or "Both".
    
    .EXAMPLE
        Get-CSPDirectoryReport -TenantId "contoso.onmicrosoft.com" -TenantName "Contoso" -OutputPath "C:\Reports" -OutputFormat "CSV"
    #>
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
        [string]$OutputFormat = "CSV"
    )
    
    try {
        Write-Verbose "Generating directory report for tenant $TenantName"
        
        # Check if connected to the correct tenant
        $connectionTest = Test-CSPConnection
        
        if (-not $connectionTest.Connected -or $connectionTest.TenantId -ne $TenantId) {
            throw "Not connected to the correct tenant. Please connect to tenant $TenantId first."
        }
        
        # Get organization information
        Write-Verbose "Retrieving organization information"
        $organization = Get-MgOrganization
        
        # Get domains
        Write-Verbose "Retrieving domains"
        $domains = Get-MgDomain
        
        # Get user count
        Write-Verbose "Retrieving user count"
        $userCount = (Get-MgUser -Count -ConsistencyLevel eventual).Count
        
        # Get group count
        Write-Verbose "Retrieving group count"
        $groupCount = (Get-MgGroup -Count -ConsistencyLevel eventual).Count
        
        # Get application count
        Write-Verbose "Retrieving application count"
        $appCount = (Get-MgApplication -Count -ConsistencyLevel eventual).Count
        
        # Create directory report
        $directoryReport = [PSCustomObject]@{
            TenantName = $TenantName
            TenantId = $TenantId
            DisplayName = $organization.DisplayName
            VerifiedDomains = ($domains | Where-Object { $_.IsVerified } | Select-Object -ExpandProperty Id) -join ", "
            UnverifiedDomains = ($domains | Where-Object { -not $_.IsVerified } | Select-Object -ExpandProperty Id) -join ", "
            UserCount = $userCount
            GroupCount = $groupCount
            ApplicationCount = $appCount
            CreatedDateTime = $organization.CreatedDateTime
            TechnicalNotificationMails = $organization.TechnicalNotificationMails -join ", "
            SecurityComplianceNotificationMails = $organization.SecurityComplianceNotificationMails -join ", "
            PrivacyProfile = $organization.PrivacyProfile.ContactEmail
            ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        # Export the report
        $fileName = Format-CSPReportFileName -ReportType "Directory" -TenantName $TenantName
        Export-CSPReportData -Data $directoryReport -OutputPath $OutputPath -FileName $fileName -OutputFormat $OutputFormat
        
        Write-Verbose "Directory report for tenant $TenantName completed"
        return $directoryReport
    }
    catch {
        Write-Error "Error in Get-CSPDirectoryReport: $_"
        return $null
    }
}

function Get-CSPUsageReport {
    <#
    .SYNOPSIS
        Generates usage reports for a tenant.
    
    .DESCRIPTION
        Retrieves usage reports from Microsoft Graph API and generates a report.
    
    .PARAMETER TenantId
        The tenant ID (GUID) or domain name of the tenant.
    
    .PARAMETER TenantName
        The display name of the tenant for reporting purposes.
    
    .PARAMETER OutputPath
        The path where the report will be saved.
    
    .PARAMETER OutputFormat
        The format(s) to export the report to. Valid values are "CSV", "JSON", or "Both".
    
    .PARAMETER Period
        The period for the usage report. Valid values are "D7", "D30", "D90", "D180". Default is "D30".
    
    .EXAMPLE
        Get-CSPUsageReport -TenantId "contoso.onmicrosoft.com" -TenantName "Contoso" -OutputPath "C:\Reports" -OutputFormat "CSV" -Period "D30"
    #>
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
        [ValidateSet("D7", "D30", "D90", "D180")]
        [string]$Period = "D30"
    )
    
    try {
        Write-Verbose "Generating usage reports for tenant $TenantName"
        
        # Check if connected to the correct tenant
        $connectionTest = Test-CSPConnection
        
        if (-not $connectionTest.Connected -or $connectionTest.TenantId -ne $TenantId) {
            throw "Not connected to the correct tenant. Please connect to tenant $TenantId first."
        }
        
        # Get Microsoft 365 service usage report
        Write-Verbose "Retrieving Microsoft 365 service usage report"
        $m365UsageReport = Get-MgReportM365AppUserDetail -Period $Period
        
        # Process usage report
        $usageReport = @()
        
        foreach ($report in $m365UsageReport) {
            # Create report entry
            $reportEntry = [PSCustomObject]@{
                TenantName = $TenantName
                UserPrincipalName = $report.UserPrincipalName
                DisplayName = $report.DisplayName
                LastActivationDate = $report.LastActivationDate
                LastActivityDate = $report.LastActivityDate
                ReportRefreshDate = $report.ReportRefreshDate
                ProductsAssigned = $report.ProductsAssigned
                ProductsUsed = $report.ProductsUsed
                ReportPeriod = $Period
                ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            
            $usageReport += $reportEntry
        }
        
        # Export the report
        $fileName = Format-CSPReportFileName -ReportType "Usage" -TenantName $TenantName
        Export-CSPReportData -Data $usageReport -OutputPath $OutputPath -FileName $fileName -OutputFormat $OutputFormat
        
        Write-Verbose "Usage report for tenant $TenantName completed"
        return $usageReport
    }
    catch {
        Write-Error "Error in Get-CSPUsageReport: $_"
        return $null
    }
}
#endregion

# Export public functions
Export-ModuleMember -Function Get-CSPMFAReport, Get-CSPAuditLogReport, Get-CSPDirectoryReport, Get-CSPUsageReport