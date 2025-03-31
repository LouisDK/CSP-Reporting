# Multi-Tenant Graph API Reporting System Design

## System Overview

This system will automate Microsoft Graph API queries across multiple tenant environments for your MSP (Netsurit), focusing on security and compliance reporting through app-only authentication.

## Core Components

### 1. Configuration Module

**File: `Config.psm1`**
- Handles loading of configuration settings
- Securely manages authentication credentials
- Defines tenant list and connection parameters

### 2. Authentication Module

**File: `Auth.psm1`**
- Manages Microsoft Graph API authentication
- Implements client credentials flow for app-only authentication
- Supports both certificate and client secret authentication methods
- Handles token management and renewal

### 3. Core Reporting Engine

**File: `ReportingEngine.psm1`**
- Provides the framework for multi-tenant reporting
- Manages tenant connections
- Coordinates report generation
- Handles error conditions and logging

### 4. Individual Report Modules

Separate module files for each report type:

**File: `MFAReport.psm1`**
- Retrieves and analyzes MFA status for all users
- Identifies users without MFA configured

**File: `AuditLogReport.psm1`**
- Retrieves directory audit logs
- Handles pagination and rate limiting
- Processes sign-in events

**File: `InactiveUserReport.psm1`**
- Identifies users who haven't signed in for a defined period
- Cross-references against Azure AD sign-in logs

**File: `LicenseReport.psm1`**
- Retrieves license allocation information
- Calculates usage metrics and potential cost savings

### 5. Output Handlers

**File: `OutputHandlers.psm1`**
- Manages report output formats (CSV, JSON)
- Creates summary reports
- Handles file naming and storage

### 6. Main Execution Script

**File: `Run-MultiTenantReports.ps1`**
- Main entry point for the system
- Processes command-line arguments
- Loads required modules
- Invokes the reporting engine

## System Flow

1. The main script loads configuration from JSON or parameters
2. Authentication is established with each tenant using app-only flow
3. For each tenant, the specified reports are generated
4. Results are processed and saved in the specified formats
5. A master summary is generated across all tenants

## Configuration Structure

The system uses a JSON configuration file:

```json
{
  "ClientId": "your-app-registration-client-id",
  "ClientSecret": "your-client-secret", 
  "CertificateThumbprint": "your-certificate-thumbprint",
  "UseCertificateAuth": true,
  "OutputFolder": "./Reports",
  "LogLevel": "Info",
  "Tenants": [
    {
      "TenantId": "tenant1.onmicrosoft.com",
      "TenantName": "Client 1"
    },
    {
      "TenantId": "tenant2.onmicrosoft.com",
      "TenantName": "Client 2"
    }
  ],
  "ReportSettings": {
    "MFAReport": {
      "IncludeGuests": false
    },
    "AuditLogReport": {
      "DaysToRetrieve": 7
    },
    "InactiveUserReport": {
      "InactiveThresholdDays": 30
    }
  }
}
```

## Required Graph API Permissions

Your Enterprise application requires these permissions:

- `User.Read.All` - For user information and MFA status
- `AuditLog.Read.All` - For audit log data
- `Directory.Read.All` - For tenant directory information
- `Reports.Read.All` - For usage reports

## Key Technical Considerations

1. **Authentication**:
   - Certificate-based authentication is more secure than client secrets
   - App-only authentication eliminates the need for user interaction

2. **Performance**:
   - Graph API has throttling limits that must be handled
   - Pagination is required for large datasets

3. **Error Handling**:
   - Robust retry logic for transient failures
   - Tenant-specific failure shouldn't fail the entire process

4. **Security**:
   - Credentials should be stored securely
   - Certificate private keys must be properly protected

5. **Scheduling**:
   - System can be executed on demand or scheduled

## Extensibility Points

1. **New Report Types**:
   - Create additional report modules following the standard template
   - Register new report types in the configuration file

2. **Custom Output Formats**:
   - Extend the output handlers to support new formats
   - Add direct database connections if needed

3. **Integration**:
   - Results can be sent to external systems via API calls
   - Email notifications can be added for report completion or issues

This modular approach ensures each component has a single responsibility, making the system easier to maintain and extend. The system is designed to be robust against API throttling and temporary failures, with proper logging for troubleshooting.