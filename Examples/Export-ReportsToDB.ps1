<#
.SYNOPSIS
    Sample script for exporting CSP reports to a SQL database.

.DESCRIPTION
    This script demonstrates how to export CSP reports to a SQL database
    for further analysis or integration with other systems.

.NOTES
    File Name      : Export-ReportsToDB.ps1
    Prerequisite   : PowerShell Core 7.0 or later
                     Microsoft Graph PowerShell SDK
                     CSP Reporting solution
                     SQL Server or SQL Express

.EXAMPLE
    .\Export-ReportsToDB.ps1 -ServerInstance "localhost\SQLEXPRESS" -Database "CSPReports" -ReportTypes MFA,AuditLog
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$ServerInstance,
    
    [Parameter(Mandatory = $true)]
    [string]$Database,
    
    [Parameter(Mandatory = $false)]
    [string]$Username,
    
    [Parameter(Mandatory = $false)]
    [SecureString]$Password,
    
    [Parameter(Mandatory = $false)]
    [switch]$UseIntegratedSecurity = $true,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("MFA", "AuditLog", "DirectoryInfo", "UsageReports", "All")]
    [string[]]$ReportTypes = @("All"),
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "..\Config.psd1",
    
    [Parameter(Mandatory = $false)]
    [string]$ReportsPath = $null,
    
    [Parameter(Mandatory = $false)]
    [switch]$CreateTables = $true
)

#region Script Initialization
# Set strict mode to catch common errors
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Script root path
$ScriptPath = $PSScriptRoot
$RootPath = Split-Path -Path $ScriptPath -Parent
$ModulesPath = Join-Path -Path $RootPath -ChildPath "Modules"

# Import required modules
try {
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "Auth.psm1") -Force
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "Reports.psm1") -Force
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "Utilities.psm1") -Force
    
    # Check if Microsoft Graph module is installed
    if (-not (Get-Module -Name Microsoft.Graph -ListAvailable)) {
        Write-Warning "Microsoft Graph PowerShell SDK is not installed. Installing..."
        Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force
    }
    
    # Check if SqlServer module is installed
    if (-not (Get-Module -Name SqlServer -ListAvailable)) {
        Write-Warning "SqlServer module is not installed. Installing..."
        Install-Module -Name SqlServer -Scope CurrentUser -Force
    }
    
    Import-Module -Name SqlServer -Force
}
catch {
    Write-Error "Failed to import required modules: $_"
    exit 1
}
#endregion

#region Load Configuration
try {
    Write-Verbose "Loading configuration from $ConfigPath"
    $Config = Import-PowerShellDataFile -Path $ConfigPath
    
    # Validate configuration
    $requiredSettings = @("AppRegistration", "TenantConfigs")
    foreach ($setting in $requiredSettings) {
        if (-not $Config.ContainsKey($setting)) {
            throw "Required configuration setting '$setting' is missing"
        }
    }
    
    # Set reports path
    if (-not $ReportsPath) {
        $ReportsPath = $Config.OutputPath
    }
}
catch {
    Write-Error "Failed to load configuration: $_"
    exit 1
}
#endregion

#region Helper Functions
function New-SqlConnectionString {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServerInstance,
        
        [Parameter(Mandatory = $true)]
        [string]$Database,
        
        [Parameter(Mandatory = $false)]
        [string]$Username,
        
        [Parameter(Mandatory = $false)]
        [SecureString]$Password,
        
        [Parameter(Mandatory = $false)]
        [bool]$UseIntegratedSecurity = $true
    )
    
    try {
        $connectionString = "Server=$ServerInstance;Database=$Database;"
        
        if ($UseIntegratedSecurity) {
            $connectionString += "Integrated Security=True;"
        }
        else {
            if (-not $Username -or -not $Password) {
                throw "Username and Password are required when not using Integrated Security"
            }
            
            # Convert secure string to plain text
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            
            $connectionString += "User Id=$Username;Password=$plainPassword;"
        }
        
        return $connectionString
    }
    catch {
        Write-Error "Error in New-SqlConnectionString: $_"
        return $null
    }
}

function Test-SqlConnection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ConnectionString
    )
    
    try {
        $connection = New-Object System.Data.SqlClient.SqlConnection
        $connection.ConnectionString = $ConnectionString
        $connection.Open()
        $connection.Close()
        
        return $true
    }
    catch {
        Write-Error "Error testing SQL connection: $_"
        return $false
    }
}

function New-SqlDatabase {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServerInstance,
        
        [Parameter(Mandatory = $true)]
        [string]$Database,
        
        [Parameter(Mandatory = $false)]
        [string]$Username,
        
        [Parameter(Mandatory = $false)]
        [SecureString]$Password,
        
        [Parameter(Mandatory = $false)]
        [bool]$UseIntegratedSecurity = $true
    )
    
    try {
        # Create connection string to master database
        $masterConnectionString = New-SqlConnectionString -ServerInstance $ServerInstance -Database "master" -Username $Username -Password $Password -UseIntegratedSecurity $UseIntegratedSecurity
        
        # Check if database exists
        $query = "SELECT COUNT(*) FROM sys.databases WHERE name = '$Database'"
        $result = Invoke-Sqlcmd -ConnectionString $masterConnectionString -Query $query
        
        if ($result.Column1 -eq 0) {
            # Create database
            $query = "CREATE DATABASE [$Database]"
            Invoke-Sqlcmd -ConnectionString $masterConnectionString -Query $query
            
            Write-Host "Database '$Database' created successfully" -ForegroundColor Green
        }
        else {
            Write-Verbose "Database '$Database' already exists"
        }
        
        return $true
    }
    catch {
        Write-Error "Error creating database: $_"
        return $false
    }
}

function New-SqlTables {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ConnectionString
    )
    
    try {
        # Create MFA report table
        $query = @"
IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[MFAReport]') AND type in (N'U'))
BEGIN
    CREATE TABLE [dbo].[MFAReport](
        [Id] [int] IDENTITY(1,1) NOT NULL,
        [TenantName] [nvarchar](255) NOT NULL,
        [UserId] [nvarchar](255) NOT NULL,
        [DisplayName] [nvarchar](255) NULL,
        [UserPrincipalName] [nvarchar](255) NOT NULL,
        [AccountEnabled] [bit] NOT NULL,
        [UserType] [nvarchar](50) NULL,
        [MFAEnabled] [bit] NOT NULL,
        [MFAMethods] [nvarchar](max) NULL,
        [ReportDate] [datetime] NOT NULL,
        CONSTRAINT [PK_MFAReport] PRIMARY KEY CLUSTERED ([Id] ASC)
    )
END
"@
        Invoke-Sqlcmd -ConnectionString $ConnectionString -Query $query
        
        # Create Audit Log report table
        $query = @"
IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[AuditLogReport]') AND type in (N'U'))
BEGIN
    CREATE TABLE [dbo].[AuditLogReport](
        [Id] [int] IDENTITY(1,1) NOT NULL,
        [TenantName] [nvarchar](255) NOT NULL,
        [ActivityDateTime] [datetime] NOT NULL,
        [ActivityDisplayName] [nvarchar](255) NULL,
        [Category] [nvarchar](100) NULL,
        [CorrelationId] [nvarchar](255) NULL,
        [InitiatedBy] [nvarchar](255) NULL,
        [InitiatorType] [nvarchar](50) NULL,
        [Result] [nvarchar](50) NULL,
        [ResultReason] [nvarchar](max) NULL,
        [LogId] [nvarchar](255) NULL,
        [ReportDate] [datetime] NOT NULL,
        CONSTRAINT [PK_AuditLogReport] PRIMARY KEY CLUSTERED ([Id] ASC)
    )
END
"@
        Invoke-Sqlcmd -ConnectionString $ConnectionString -Query $query
        
        # Create Directory report table
        $query = @"
IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[DirectoryReport]') AND type in (N'U'))
BEGIN
    CREATE TABLE [dbo].[DirectoryReport](
        [Id] [int] IDENTITY(1,1) NOT NULL,
        [TenantName] [nvarchar](255) NOT NULL,
        [TenantId] [nvarchar](255) NOT NULL,
        [DisplayName] [nvarchar](255) NULL,
        [VerifiedDomains] [nvarchar](max) NULL,
        [UnverifiedDomains] [nvarchar](max) NULL,
        [UserCount] [int] NULL,
        [GroupCount] [int] NULL,
        [ApplicationCount] [int] NULL,
        [CreatedDateTime] [datetime] NULL,
        [TechnicalNotificationMails] [nvarchar](max) NULL,
        [SecurityComplianceNotificationMails] [nvarchar](max) NULL,
        [PrivacyProfile] [nvarchar](255) NULL,
        [ReportDate] [datetime] NOT NULL,
        CONSTRAINT [PK_DirectoryReport] PRIMARY KEY CLUSTERED ([Id] ASC)
    )
END
"@
        Invoke-Sqlcmd -ConnectionString $ConnectionString -Query $query
        
        # Create Usage report table
        $query = @"
IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[UsageReport]') AND type in (N'U'))
BEGIN
    CREATE TABLE [dbo].[UsageReport](
        [Id] [int] IDENTITY(1,1) NOT NULL,
        [TenantName] [nvarchar](255) NOT NULL,
        [UserPrincipalName] [nvarchar](255) NOT NULL,
        [DisplayName] [nvarchar](255) NULL,
        [LastActivationDate] [datetime] NULL,
        [LastActivityDate] [datetime] NULL,
        [ReportRefreshDate] [datetime] NULL,
        [ProductsAssigned] [nvarchar](max) NULL,
        [ProductsUsed] [nvarchar](max) NULL,
        [ReportPeriod] [nvarchar](10) NULL,
        [ReportDate] [datetime] NOT NULL,
        CONSTRAINT [PK_UsageReport] PRIMARY KEY CLUSTERED ([Id] ASC)
    )
END
"@
        Invoke-Sqlcmd -ConnectionString $ConnectionString -Query $query
        
        Write-Host "Database tables created successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Error creating database tables: $_"
        return $false
    }
}

function Import-CSVToSql {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$CsvPath,
        
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        
        [Parameter(Mandatory = $true)]
        [string]$ConnectionString
    )
    
    try {
        # Check if CSV file exists
        if (-not (Test-Path -Path $CsvPath)) {
            Write-Warning "CSV file not found: $CsvPath"
            return $false
        }
        
        # Import CSV data
        $csvData = Import-Csv -Path $CsvPath
        
        if ($csvData.Count -eq 0) {
            Write-Warning "No data found in CSV file: $CsvPath"
            return $false
        }
        
        # Get column names from CSV
        $columns = $csvData[0].PSObject.Properties.Name
        
        # Create SQL connection
        $connection = New-Object System.Data.SqlClient.SqlConnection
        $connection.ConnectionString = $ConnectionString
        $connection.Open()
        
        # Create SQL command
        $command = $connection.CreateCommand()
        
        # Process each row
        $rowCount = 0
        
        foreach ($row in $csvData) {
            # Build insert statement
            $columnList = $columns -join ", "
            $paramList = "@" + ($columns -join ", @")
            
            $command.CommandText = "INSERT INTO [$TableName] ($columnList) VALUES ($paramList)"
            
            # Add parameters
            $command.Parameters.Clear()
            
            foreach ($column in $columns) {
                $param = $command.CreateParameter()
                $param.ParameterName = "@$column"
                $param.Value = if ($null -eq $row.$column) { [DBNull]::Value } else { $row.$column }
                $command.Parameters.Add($param) | Out-Null
            }
            
            # Execute command
            $rowCount += $command.ExecuteNonQuery()
        }
        
        # Close connection
        $connection.Close()
        
        Write-Host "Imported $rowCount rows to table $TableName" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Error importing CSV to SQL: $_"
        return $false
    }
}
#endregion

#region Main Execution
try {
    Write-Host "Starting CSP Reports to SQL Database export at $(Get-Date)" -ForegroundColor Green
    
    # Create connection string
    $connectionString = New-SqlConnectionString -ServerInstance $ServerInstance -Database $Database -Username $Username -Password $Password -UseIntegratedSecurity $UseIntegratedSecurity
    
    if (-not $connectionString) {
        throw "Failed to create connection string"
    }
    
    # Create database if it doesn't exist
    $dbResult = New-SqlDatabase -ServerInstance $ServerInstance -Database $Database -Username $Username -Password $Password -UseIntegratedSecurity $UseIntegratedSecurity
    
    if (-not $dbResult) {
        throw "Failed to create database"
    }
    
    # Create tables if requested
    if ($CreateTables) {
        $tablesResult = New-SqlTables -ConnectionString $connectionString
        
        if (-not $tablesResult) {
            throw "Failed to create database tables"
        }
    }
    
    # Test connection
    $connectionTest = Test-SqlConnection -ConnectionString $connectionString
    
    if (-not $connectionTest) {
        throw "Failed to connect to database"
    }
    
    # Determine which reports to process
    $reportsToProcess = if ($ReportTypes -contains "All") {
        @("MFA", "AuditLog", "Directory", "Usage")
    } else {
        $ReportTypes
    }
    
    # Process each report type
    foreach ($reportType in $reportsToProcess) {
        Write-Host "Processing $reportType reports..." -ForegroundColor Yellow
        
        # Find report files
        $reportFiles = Get-ChildItem -Path $ReportsPath -Filter "${reportType}_*.csv" -File
        
        if ($reportFiles.Count -eq 0) {
            Write-Warning "No $reportType report files found in $ReportsPath"
            continue
        }
        
        # Map report type to table name
        $tableName = switch ($reportType) {
            "MFA" { "MFAReport" }
            "AuditLog" { "AuditLogReport" }
            "Directory" { "DirectoryReport" }
            "Usage" { "UsageReport" }
            default { "${reportType}Report" }
        }
        
        # Import each report file
        foreach ($file in $reportFiles) {
            Write-Host "  Importing $($file.Name)..." -ForegroundColor Cyan
            $importResult = Import-CSVToSql -CsvPath $file.FullName -TableName $tableName -ConnectionString $connectionString
            
            if (-not $importResult) {
                Write-Warning "  Failed to import $($file.Name)"
            }
        }
    }
    
    Write-Host "CSP Reports to SQL Database export completed at $(Get-Date)" -ForegroundColor Green
}
catch {
    Write-Error "An error occurred during export: $_"
}
#endregion
