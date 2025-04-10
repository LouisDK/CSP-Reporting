Okay, let's craft an article detailing the essential Microsoft Graph API data sources required to fuel your advanced multi-tenant reporting framework. This focuses on *what data to extract* and *why*, laying the groundwork for the subsequent analysis and LLM summarization stages.

---

## Powering Insight: Graph API Data Sources for Comprehensive M365 Tenant Reporting

**Introduction**

Our goal is to build a robust, multi-tenant Microsoft 365 reporting framework that goes beyond simple inventory lists. We aim for *actionable intelligence* – identifying security gaps, misconfigurations, and potential risks proactively. This requires gathering a rich dataset directly from the Microsoft Graph API, the central nervous system for Microsoft 365 data.

While the existing framework successfully extracts data like MFA status (as seen in `Get-CSPMFAReport`), it primarily focuses on individual data points. To achieve comprehensive security posture reporting, we need to significantly expand the scope of data collection. This article details the specific Graph API queries and data points needed as the foundation for our analysis engine.

**Core Principle: Data Extraction First, Analysis Second**

This article focuses solely on the **data extraction** phase. We will identify the necessary Graph API endpoints, the specific properties (`select` parameters) to retrieve, and relevant filters (`filter` parameters) to ensure we gather all required raw data efficiently. The framework's existing capabilities (like `Invoke-CSPWithRetry`, pagination handling, state management) will be leveraged to execute these queries reliably across tenants. The subsequent step, analyzing this data to generate insights and findings (like the `TenantName_Insights.json` discussed previously), builds upon this foundation.

**Methodology: Querying the Graph API**

For each key reporting area, we will outline:

1.  **Primary Graph API Endpoint(s) / PowerShell Cmdlet(s):** The target location for the data. We'll primarily use the `v1.0` endpoint unless `beta` is necessary.
2.  **Key Properties (`$select` / `-Select`):** The specific data fields required for later analysis. Requesting only necessary properties improves performance.
3.  **Potential Filters (`$filter` / `-Filter`):** Used to narrow down results (e.g., active users, specific group types, date ranges).
4.  **Necessary Headers:** Often `ConsistencyLevel: eventual` is required for advanced queries using `$filter`, `$count`, or `$search`.
5.  **Reasoning:** Why this data is crucial for security posture assessment.

*Note:* The framework must handle pagination (`@odata.nextLink`) for all queries that return collections.

**Detailed Graph API Query Requirements**

Here's a breakdown of the data needed, area by area:

**1. Users (Inventory, Status, Activity, Licensing)**

* **Endpoint/Cmdlet:** `GET /users` | `Get-MgUser`
* **Key Properties (`-Select`):**
    * `id`: Unique identifier (essential for linking).
    * `userPrincipalName`: Primary identifier.
    * `displayName`: User-friendly name.
    * `accountEnabled`: To identify active/inactive accounts.
    * `userType`: To distinguish 'Member' from 'Guest'.
    * `creationDateTime`: To identify newly created accounts.
    * `assignedLicenses`: To check license assignment (requires parsing the `skuId`).
    * `signInActivity`: Contains `lastSignInDateTime` and `lastNonInteractiveSignInDateTime` (useful for identifying stale accounts - *Note: Requires Azure AD P1/P2 and explicit selection*).
* **Potential Filters (`-Filter`):**
    * `accountEnabled eq true` (for active users).
    * `userType eq 'Guest'` (for guest user analysis).
* **Headers:** `ConsistencyLevel: eventual` (often needed with `$count` and `$filter`). Add `$count=true` to get total user counts efficiently.
* **Reasoning:** Forms the basis of most identity-related checks. Need to know who the users are, their status, type, activity, and license assignment for MFA checks, stale account detection, guest management, and license auditing.

**2. User Authentication Methods (MFA Status)**

* **Endpoint/Cmdlet:** `GET /users/{id}/authentication/methods` | `Get-MgUserAuthenticationMethod -UserId $userId`
    * *(Note: This must be run **per user**, which can be slow. The current `Get-CSPMFAReport` implements this correctly for data gathering.)*
* **Key Properties:** The response is a collection of method objects. We need to check the `@odata.type` property of each object (e.g., `#microsoft.graph.phoneAuthenticationMethod`, `#microsoft.graph.microsoftAuthenticatorAuthenticationMethod`, etc.) to determine registered MFA/passwordless methods.
* **Reasoning:** Directly determines which strong authentication methods are registered for each user. Crucial for MFA status reporting and identifying users (especially admins) lacking MFA.

**3. Groups (Inventory, Type, Membership)**

* **Endpoint/Cmdlet:** `GET /groups` | `Get-MgGroup`
* **Key Properties (`-Select`):**
    * `id`: Unique identifier.
    * `displayName`: Group name.
    * `groupTypes`: Identifies if it's 'Unified' (Microsoft 365) or 'DynamicMembership'.
    * `securityEnabled`: Identifies security groups.
    * `mailEnabled`: Identifies mail-enabled groups/distribution lists.
    * `description`: Context about the group's purpose.
    * `visibility`: For M365 groups (Public/Private).
* **Potential Filters (`-Filter`):**
    * `securityEnabled eq true` (to focus on security groups).
* **Headers:** `ConsistencyLevel: eventual` (often needed with `$count` and `$filter`). Add `$count=true` to get total group counts.
* **Reasoning:** Needed for inventory, understanding group types used in policies, and potentially analyzing group memberships (though getting *all* members might require separate queries per group: `GET /groups/{id}/members`).

**4. Directory Roles & Privileged Identity Management (PIM)**

* **Endpoint/Cmdlet (Modern RBAC/PIM):**
    * `GET /roleManagement/directory/roleDefinitions` | `Get-MgRoleManagementDirectoryRoleDefinition` (To list available roles)
    * `GET /roleManagement/directory/roleAssignments` | `Get-MgRoleManagementDirectoryRoleAssignment` (To get active, permanent assignments)
    * `GET /roleManagement/directory/roleEligibilityScheduleInstances` | `Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance` (To get currently eligible PIM assignments)
    * `GET /roleManagement/directory/roleAssignmentScheduleInstances` | `Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance` (To get currently active time-bound PIM assignments)
* **Key Properties (`-Select`):**
    * `roleDefinitionId`: Links assignment to the role definition.
    * `principalId`: The User/SP assigned the role.
    * `directoryScopeId`: Scope of assignment (e.g., '/', '/administrativeUnits/{id}').
    * *(For Schedules):* `startDateTime`, `endDateTime`, `memberType`, `assignmentType`.
    * *(For Role Definitions):* `id`, `displayName`, `description`, `isEnabled`.
* **Reasoning:** Critical for identifying who holds privileged roles, whether permanently or via PIM. Essential for finding admins without MFA, over-privileged accounts, and auditing privileged access configurations.

**5. Conditional Access Policies**

* **Endpoint/Cmdlet:** `GET /identity/conditionalAccess/policies` | `Get-MgIdentityConditionalAccessPolicy`
* **Key Properties (`-Select`):**
    * `id`: Unique identifier.
    * `displayName`: Policy name.
    * `state`: 'enabled', 'disabled', 'enabledForReportingButNotEnforced'.
    * `conditions`: Contains users, applications, locations, platforms, devices targeted/excluded (requires parsing).
    * `grantControls`: Required controls like MFA, compliant device (requires parsing).
    * `sessionControls`: Session behaviors like sign-in frequency (requires parsing).
* **Reasoning:** CA policies are central to modern security. Need to analyze them for gaps, risky configurations (e.g., allowing legacy auth, overly broad assignments, weak controls), disabled policies, and ensuring MFA is enforced correctly.

**6. Applications & Service Principals (Permissions, Credentials)**

* **Endpoint/Cmdlet:**
    * `GET /applications` | `Get-MgApplication` (Owned App Registrations)
    * `GET /servicePrincipals` | `Get-MgServicePrincipal` (Enterprise Apps / Instantiated Apps)
* **Key Properties (`-Select`):**
    * `id`: Unique identifier.
    * `appId`: Application (client) ID.
    * `displayName`: Application name.
    * `signInAudience`: Who can use the app.
    * `keyCredentials`: Information about certificate credentials, including `endDateTime`.
    * `passwordCredentials`: Information about client secret credentials, including `endDateTime`.
    * `requiredResourceAccess` (on Application): API permissions requested by the app.
    * `publishedPermissionScopes` / `appRoles` (on Application): Permissions/roles the app exposes.
    * `servicePrincipalType`: (on ServicePrincipal) 'Application', 'ManagedIdentity', etc.
    * `tags`: (on ServicePrincipal) Useful for identifying 'WindowsAzureActiveDirectoryIntegratedApp', etc.
    * `oauth2PermissionGrants` / `appRoleAssignments` (can be queried via `/oauth2PermissionGrants` or `/appRoleAssignments` endpoints, or sometimes expanded on the SP): Permissions/roles *actually granted* to the SP. `Get-MgServicePrincipalAppRoleAssignedTo` and `Get-MgServicePrincipalOauth2PermissionGrant` might be more reliable.
* **Reasoning:** Need to identify applications with high-privilege permissions, expiring credentials, risky configurations, and understand consent grants.

**7. Device Compliance (Intune)**

* **Endpoint/Cmdlet:** `GET /deviceManagement/managedDevices` | `Get-MgDeviceManagementManagedDevice` *(Requires Intune license/permissions)*
* **Key Properties (`-Select`):**
    * `id`: Unique identifier.
    * `deviceName`: Device name.
    * `userPrincipalName`: Primary user.
    * `complianceState`: 'compliant', 'noncompliant', 'error', etc.
    * `osVersion`: Operating system version.
    * `lastSyncDateTime`: Last check-in time.
    * `managedDeviceOwnerType`: 'company', 'personal'.
    * `managementAgent`: e.g., 'mdm', 'eas'.
* **Reasoning:** To assess the security posture of devices accessing tenant resources, identify non-compliant devices, and check device activity.

**8. Identity Risk & Protection Data**

* **Endpoint/Cmdlet:**
    * `GET /identityProtection/riskyUsers` | `Get-MgRiskyUser` *(Requires AAD P1/P2)*
    * `GET /identityProtection/riskDetections` | `Get-MgRiskDetection` *(Requires AAD P2)*
* **Key Properties (`-Select`):**
    * *(Risky Users):* `id`, `userPrincipalName`, `riskLevel`, `riskState`, `riskDetail`, `riskLastUpdatedDateTime`, `isDeleted`, `isProcessing`.
    * *(Risk Detections):* `id`, `userPrincipalName`, `riskEventType`, `detectionTimingType`, `activityDateTime`, `ipAddress`, `location`, `riskLevel`, `riskState`, `riskDetail`.
* **Potential Filters (`-Filter`):**
    * `riskState eq 'atRisk'` or `riskLevel eq 'high'` / `'medium'` (for risky users).
    * Date range filters on `activityDateTime` (for detections).
* **Reasoning:** To identify compromised accounts, risky sign-ins, and leverage Azure AD Identity Protection insights for proactive threat response.

**9. Tenant Configuration Settings**

* **Endpoint/Cmdlet:**
    * `GET /policies/identitySecurityDefaultsEnforcementPolicy` | `Get-MgPolicyIdentitySecurityDefaultsEnforcementPolicy`
    * `GET /policies/authenticationMethodsPolicy` | `Get-MgPolicyAuthenticationMethodPolicy` (and specific methods like `GET /policies/authenticationMethodsPolicy/authenticationMethodConfigurations/microsoftAuthenticator`)
    * `GET /policies/authorizationPolicy` | `Get-MgPolicyAuthorizationPolicy`
    * `GET /domains` | `Get-MgDomain`
    * `GET /organization` | `Get-MgOrganization`
* **Key Properties (`-Select`):**
    * *(Security Defaults):* `isEnabled`.
    * *(Auth Methods):* Settings for each configured method.
    * *(Authorization Policy):* `allowInvitesFrom`, `allowedToUseSSPR`, `allowLegacyServicePrincipalLogins`, `blockMsolPowerShell`.
    * *(Domains):* `id`, `isVerified`, `authenticationType` (Managed/Federated).
    * *(Organization):* `id`, `displayName`, `technicalNotificationMails`, `securityComplianceNotificationMails`, `mobileDeviceManagementAuthority`.
* **Reasoning:** To verify baseline security settings like Security Defaults status, enabled authentication methods, SSPR configuration, legacy protocol status, verified domains, and key organizational contacts.

**10. Audit Logs & Usage Reports**

* **Endpoint/Cmdlet:**
    * `GET /auditLogs/directoryAudits` | `Get-MgAuditLogDirectoryAudit`
    * `GET /auditLogs/signIns` | `Get-MgAuditLogSignIn`
    * `GET /reports/` (various endpoints for specific usage reports) | Various `Get-MgReport*` cmdlets
* **Key Properties (`-Select`):** Varies greatly depending on the log/report. Typically includes `activityDateTime`, `activityDisplayName`, `category`, `correlationId`, `result`, `resultReason`, user/actor details (`userPrincipalName`, `ipAddress`), target resource details.
* **Potential Filters (`-Filter`):** **Crucial** here. Filter by date range (`activityDateTime ge ... and activityDateTime le ...`), `category`, `activityDisplayName`, `result`, `userPrincipalName`.
* **Reasoning:** Provide historical data for investigations, track specific activities (e.g., role assignments, policy changes), and analyze sign-in patterns (including legacy auth usage).

**Handling Complexity**

Executing these queries requires robust handling of:

* **Pagination:** Consistently processing `@odata.nextLink`.
* **Throttling:** Implementing retry logic with backoff (`Invoke-CSPWithRetry`).
* **Error Handling:** Gracefully managing errors if data isn't available (e.g., due to licensing).
* **Parsing:** Extracting relevant data from complex objects (e.g., CA conditions, license details).

---
