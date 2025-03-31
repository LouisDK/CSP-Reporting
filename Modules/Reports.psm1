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
        and generates a report.
    
    .PARAMETER TenantId
        The tenant ID (GUID) or domain name of the tenant.
    
    .PARAMETER TenantName
        The display name of the tenant for reporting purposes.
    
    .PARAMETER OutputPath
        The path where the report will be saved.
    
    .PARAMETER OutputFormat
        The format(s) to export the report to. Valid values are "CSV", "JSON", or "Both".
    
    .EXAMPLE
        Get-CSPMFAReport -TenantId "contoso.onmicrosoft.com" -TenantName "Contoso" -OutputPath "C:\Reports" -OutputFormat "CSV"
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
        Write-Verbose "Generating MFA report for tenant $TenantName"
        
        # Check if connected to the correct tenant
        $connectionTest = Test-CSPConnection
        
        if (-not $connectionTest.Connected -or $connectionTest.TenantId -ne $TenantId) {
            throw "Not connected to the correct tenant. Please connect to tenant $TenantId first."
        }
        
        # Get all users
        Write-Verbose "Retrieving users from tenant $TenantName"
        $users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AccountEnabled, UserType
        
        # Get authentication methods for each user
        $mfaReport = @()
        
        foreach ($user in $users) {
            Write-Verbose "Processing user $($user.UserPrincipalName)"
            
            try {
                # Get authentication methods
                $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id
                
                # Determine MFA status
                $mfaEnabled = $false
                $mfaMethods = @()
                
                foreach ($method in $authMethods) {
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
                Write-Warning "Error processing user $($user.UserPrincipalName): $_"
                
                # Add user to report with error
                $reportEntry = [PSCustomObject]@{
                    TenantName = $TenantName
                    UserId = $user.Id
                    DisplayName = $user.DisplayName
                    UserPrincipalName = $user.UserPrincipalName
                    AccountEnabled = $user.AccountEnabled
                    UserType = $user.UserType
                    MFAEnabled = "Error"
                    MFAMethods = "Error: $_"
                    ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
                
                $mfaReport += $reportEntry
            }
        }
        
        # Export the report
        $fileName = Format-CSPReportFileName -ReportType "MFA" -TenantName $TenantName
        Export-CSPReportData -Data $mfaReport -OutputPath $OutputPath -FileName $fileName -OutputFormat $OutputFormat
        
        Write-Verbose "MFA report for tenant $TenantName completed"
        return $mfaReport
    }
    catch {
        Write-Error "Error in Get-CSPMFAReport: $_"
        return $null
    }
}

function Get-CSPAuditLogReport {
    <#
    .SYNOPSIS
        Generates an audit log report for a tenant.
    
    .DESCRIPTION
        Retrieves audit log data from Microsoft Graph API and generates a report.
    
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
    
    .EXAMPLE
        Get-CSPAuditLogReport -TenantId "contoso.onmicrosoft.com" -TenantName "Contoso" -OutputPath "C:\Reports" -OutputFormat "CSV" -DaysBack 7
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
        [int]$DaysBack = 30
    )
    
    try {
        Write-Verbose "Generating audit log report for tenant $TenantName"
        
        # Check if connected to the correct tenant
        $connectionTest = Test-CSPConnection
        
        if (-not $connectionTest.Connected -or $connectionTest.TenantId -ne $TenantId) {
            throw "Not connected to the correct tenant. Please connect to tenant $TenantId first."
        }
        
        # Calculate date range
        $endDate = Get-Date
        $startDate = $endDate.AddDays(-$DaysBack)
        
        # Format dates for Graph API
        $startDateString = $startDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
        $endDateString = $endDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        Write-Verbose "Retrieving audit logs from $startDateString to $endDateString"
        
        # Get audit logs
        $filter = "activityDateTime ge $startDateString and activityDateTime le $endDateString"
        $auditLogs = Get-MgAuditLogDirectoryAudit -Filter $filter -All
        
        # Process audit logs
        $auditReport = @()
        
        foreach ($log in $auditLogs) {
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
        }
        
        # Export the report
        $fileName = Format-CSPReportFileName -ReportType "AuditLog" -TenantName $TenantName
        Export-CSPReportData -Data $auditReport -OutputPath $OutputPath -FileName $fileName -OutputFormat $OutputFormat
        
        Write-Verbose "Audit log report for tenant $TenantName completed"
        return $auditReport
    }
    catch {
        Write-Error "Error in Get-CSPAuditLogReport: $_"
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