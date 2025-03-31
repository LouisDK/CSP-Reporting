# CSP Reporting Framework Enhancements

This document describes the enhancements we've added to the CSP Reporting Framework based on our analysis of alternative scripts. These improvements enhance the usability, reliability, and presentation of the framework.

## Table of Contents

- [CSP Reporting Framework Enhancements](#csp-reporting-framework-enhancements)
  - [Table of Contents](#table-of-contents)
  - [Enhanced Module Management](#enhanced-module-management)
    - [Usage Example](#usage-example)
  - [Color-Coded Terminal Output](#color-coded-terminal-output)
    - [Usage Example](#usage-example-1)
  - [Automated Consent Management](#automated-consent-management)
    - [Usage Example](#usage-example-2)
  - [Demo Scripts](#demo-scripts)

## Enhanced Module Management

We've implemented comprehensive module management capabilities inspired by alternative approaches. The new `Initialize-CSPModules` function provides:

- Automatic detection of required modules
- Installation of missing modules
- Cleanup of older module versions
- Update detection and installation
- Detailed status reporting

### Usage Example

```powershell
# Check and initialize modules
$requiredModules = @("Microsoft.Graph", "Az.Accounts")
$results = Initialize-CSPModules -ModuleNames $requiredModules

# Force reinstallation of modules
Initialize-CSPModules -ModuleNames $requiredModules -Force
```

You can also use the standalone script `Initialize-CSPModules.ps1` to check and initialize all required modules for the CSP Reporting framework:

```powershell
.\Initialize-CSPModules.ps1
```

## Color-Coded Terminal Output

We've added enhanced visual output capabilities to make the user interface more intuitive and readable. The following new functions enable color-coded terminal output:

- `Initialize-CSPTerminalColors` - Initializes and stores original terminal colors
- `Set-CSPTerminalColors` - Sets or restores terminal colors
- `Write-CSPColorMessage` - Writes color-coded messages with foreground and background colors

You can also use the enhanced `Write-CSPLog` function with the `-UseColor` parameter for automatic color-coding based on message severity.

### Usage Example

```powershell
# Initialize terminal colors
Initialize-CSPTerminalColors

# Write color-coded messages using predefined types
Write-CSPColorMessage -Message "This is an info message" -Type Info
Write-CSPColorMessage -Message "This is a success message" -Type Success
Write-CSPColorMessage -Message "This is a warning message" -Type Warning
Write-CSPColorMessage -Message "This is an error message" -Type Error

# Write color-coded messages using custom colors
Write-CSPColorMessage -Message "Custom colored message" -ForegroundColor Yellow -BackgroundColor Blue

# Use enhanced logging with color
Write-CSPLog -Message "Operation succeeded" -Level "SUCCESS" -UseColor

# Restore original terminal colors
Set-CSPTerminalColors -RestoreOriginal
```

To see a full demonstration of the color-coded output capabilities, run the demo script:

```powershell
.\Examples\Write-CSPColorDemo.ps1
```

## Automated Consent Management

We've enhanced the framework with automated consent capabilities for multi-tenant scenarios. The new `Invoke-CSPAdminConsent` function simplifies the process of granting admin consent for applications in customer tenants:

- Automated admin consent request submission
- Support for both certificate and client secret authentication
- Fallback to manual consent URLs when automated process fails
- Detailed status reporting

### Usage Example

```powershell
# Automated admin consent using certificate authentication
$consentParams = @{
    ClientId = "00000000-0000-0000-0000-000000000000"
    CertificatePath = ".\Certificates\AppCert.pfx"
    CertificatePassword = $securePassword
    PartnerTenantId = "partner.onmicrosoft.com"
    CustomerTenantId = "customer.onmicrosoft.com"
    AppDisplayName = "CSP Reporting App"
}

$result = Invoke-CSPAdminConsent @consentParams

# Check result
if ($result.Success) {
    Write-Host "Admin consent request submitted successfully"
} else {
    Write-Host "Manual consent URL: $($result.ManualConsentUrl)"
}
```

The updated `Grant-CSPAdminConsent.ps1` script now supports automated consent via the `-AutoConsent` parameter:

```powershell
# Test admin consent status only
.\Grant-CSPAdminConsent.ps1 -TestOnly

# Attempt automated consent for all tenants
.\Grant-CSPAdminConsent.ps1 -AutoConsent
```

## Demo Scripts

We've included the following demo scripts to showcase the new capabilities:

1. **Initialize-CSPModules.ps1** - Demonstrates enhanced module management
2. **Examples/Write-CSPColorDemo.ps1** - Demonstrates color-coded terminal output capabilities

These demos provide practical examples of how to use these enhancements in your own scripts and workflows.

---

These enhancements make the CSP Reporting Framework more user-friendly and robust, particularly for interactive operations and setup processes. The improved visual feedback, module management, and consent automation significantly reduce the time and complexity involved in deploying and using the framework across multiple tenants.