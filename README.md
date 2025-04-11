# Multi-Tenant Microsoft Graph API Reporting Framework v2

A modular, enterprise-grade PowerShell framework for **deep security and compliance insights** across multiple Microsoft 365 tenants. Designed for MSPs and multi-tenant admins, it combines **comprehensive data extraction** with an **intelligent analysis engine** that generates **actionable, LLM-ready insights**.

Created by Louis de Klerk (Netsurit), April 2025.

---

## Table of Contents

- [Multi-Tenant Microsoft Graph API Reporting Framework v2](#multi-tenant-microsoft-graph-api-reporting-framework-v2)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Usage](#usage)
    - [Basic Run](#basic-run)
    - [Options](#options)
    - [What it does](#what-it-does)
  - [Data Extraction \& Analysis](#data-extraction--analysis)
  - [Insights JSON Structure](#insights-json-structure)
  - [Scheduling](#scheduling)
  - [Resilient Operations](#resilient-operations)
  - [Troubleshooting](#troubleshooting)
  - [Security Considerations](#security-considerations)

---

## Features

- **Multi-tenant Support**: Automate reporting across unlimited tenants
- **Modular Architecture**: Clean separation of data extraction and analysis layers
- **Deep Data Coverage**:
  - Users, MFA, Guest activity
  - Privileged roles & PIM assignments
  - Conditional Access policies
  - Applications, Service Principals, permissions, credentials
  - Device compliance (Intune)
  - Identity Protection risk data
  - Tenant configuration & domains
  - Audit logs & sign-ins
- **Intelligent Analysis Engine**:
  - Configurable rules & thresholds
  - Generates structured **Insights JSON** with findings & metrics
  - Designed for LLM summarization
- **Config-Driven**: Customize rules, toggles, thresholds in `Config.psd1`
- **Flexible Authentication**: Certificate or client secret
- **Resumable & Robust**: Resume after failures, detailed logging, retry logic
- **Customizable Output**: CSV, JSON, Insights JSON
- **Automated Consent**: Streamlined admin consent process
- **Scheduling Support**: Automate via scheduled tasks
- **Color-coded Logging**: Visual feedback during execution

---

## Prerequisites

- PowerShell Core 7.0+
- Microsoft Graph PowerShell SDK
- Azure AD App Registration with:
  - `User.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`, `Reports.Read.All`
  - `Policy.Read.All`, `Application.Read.All`, `RoleManagement.Read.Directory`
  - `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`
- Admin consent granted in each tenant
- Appropriate licenses (P1/P2, Intune) for some data

---

## Installation

1. Clone or download this repo
2. Run:

```powershell
.\Initialize-CSPModules.ps1
```

3. Create an App Registration (see [App Registration Guide](AppRegistration-Guide.md))
4. Configure `Config.psd1` with tenants, auth, rules, toggles

---

## Configuration

Edit `Config.psd1`:

- **AppRegistration**: ClientId, cert path or secret
- **TenantConfigs**: List of tenants, auth method, cert/secret
- **ReportSettings**: DaysBack, include disabled/guest users
- **Analysis**:
  - `EnabledChecks`: Identity, Policies, Apps, Devices, Security
  - `StaleGuestThresholdDays`
  - `CredentialExpiryWarningDays`
  - `AdminRoles`
  - `HighRiskAppPermissions`
- **DataExtractionToggles**: IncludeDeviceData, IncludeRiskData, IncludeAuditLogs
- **Reporting**: GenerateInsightsJson, SaveRawDataFiles, OutputPath
- **LoggingSettings**: Log file path, level

See example in repo.

---

## Usage

### Basic Run

```powershell
.\Start-CSPReporting.ps1
```

### Options

- `-ConfigPath` to specify config file
- `-ReportTypes` to limit legacy CSV reports
- `-OutputFormat` CSV, JSON, Both
- `-StatePath` for resumability
- `-Resume` to continue from last run

### What it does

- Authenticates to each tenant
- Extracts **all data areas** via modular functions
- Runs **analysis engine** to generate **Insights JSON**
- Saves Insights JSON per tenant (e.g., `Reports/TenantName_Insights.json`)
- Optionally generates legacy CSV reports

---

## Data Extraction & Analysis

- **Extraction**: Modular, paged, retrying, defensive
- **Analysis**:
  - Cross-references MFA, roles, PIM, guests
  - Flags risky apps, expiring credentials
  - Analyzes CA policies for gaps
  - Summarizes risky users, risk detections
  - Checks device compliance
  - Reviews tenant config (Security Defaults, domains)
- **Configurable rules** drive findings
- **Simple Output** CSV file that lists all users, indicating who has MFA configured
- **Advanced Outputs** structured JSON ready for LLM summarization

---

## Insights JSON Structure

Example:

```json
{
  "TenantId": "tenant1.onmicrosoft.com",
  "TenantName": "Tenant 1",
  "ReportTimestamp": "2025-04-10T19:00:00Z",
  "SummaryMetrics": {
    "TotalUsers": 550,
    "EnabledUsers": 520,
    "GuestUsers": 35,
    "MFAEnabledPercent": 85.5,
    "AdminRoleAssignments": 15,
    "AdminsWithoutMFA": 2,
    "ConditionalAccessPolicies": 10,
    "RiskyCAPolicies": 1,
    "HighRiskApps": 3,
    "StaleGuests": 5,
    "SecurityDefaultsEnabled": false,
    "LegacyAuthBlocked": true,
    "CompliantDevicePercent": 92.0
  },
  "Findings": [
    {
      "FindingID": "ADM-001",
      "Category": "Privileged Access",
      "Severity": "Critical",
      "Title": "Global Administrator Account Without MFA",
      "Description": "...",
      "Details": { ... },
      "Recommendation": "..."
    },
    {
      "FindingID": "APP-001",
      "Category": "Application Security",
      "Severity": "High",
      "Title": "Application with Excessive Permissions",
      "Description": "...",
      "Details": { ... },
      "Recommendation": "..."
    }
    // More findings...
  ]
}
```

---

## Scheduling

Use `Schedule-CSPReporting.ps1` to automate runs via Windows Task Scheduler.

---

## Resilient Operations

- **Resumable** with state tracking
- **Retry logic** with backoff
- **Handles API throttling**
- **Logs errors, warnings, info, debug**

---

## Troubleshooting

- Check logs in `Logs/`
- Use `-Verbose` for more output
- Verify app permissions and admin consent
- Check licenses for PIM, Intune, Risk data
- See [App Registration Guide](AppRegistration-Guide.md)

---

## Security Considerations

- Store secrets/certs securely
- Use least privilege
- Rotate secrets/certs regularly
- Monitor access to reports
- Enable Security Defaults or equivalent CA policies

---
