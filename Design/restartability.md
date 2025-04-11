# Design Spec: Enhanced Restartability and Idempotency

## 1. Goals

This document outlines the design for enhancing the CSP Reporting framework's restartability and idempotency. The primary goals are:

*   **Resumability:** Ensure the script can reliably resume from the last successfully completed data extraction step if interrupted (e.g., due to network issues, API throttling, script termination).
*   **Idempotency:** Prevent re-extraction of data that has already been successfully retrieved within the same logical run context (typically defined as the same calendar day). Running the script multiple times on the same day should reuse previously fetched data for completed steps.
*   **Efficiency:** Minimize redundant API calls, especially in multi-tenant environments, saving time and reducing the risk of hitting API limits.
*   **Flexibility:** Allow users to force a completely fresh data extraction run, ignoring any previously cached data or state for the current day.

## 2. Proposed File Structure for Raw Data Caching

To persist extracted data, a structured file system cache will be implemented under the main configured `OutputPath`.

*   **Base Cache Directory:** A dedicated subdirectory, e.g., `_Cache`, will be created within the `OutputPath`. Using an underscore prefix helps distinguish it from final report outputs.
*   **Date-Based Isolation:** Within the cache directory, data will be organized by the date of the run (`YYYY-MM-DD` format). This isolates daily runs and facilitates cleanup.
*   **Tenant-Specific Data:** Each tenant's cached data will reside in its own subdirectory named after the `TenantName` (sanitized for filesystem compatibility).
*   **Extraction Type Files:** Inside the tenant's daily directory, individual JSON files will store the raw data for each distinct extraction type.

**Example Structure:**

```
<OutputPath>/
├── _Cache/
│   └── 2025-04-11/
│       ├── TenantA_Contoso/
│       │   ├── TenantInfo.json
│       │   ├── DomainInfo.json
│       │   ├── Users.json
│       │   ├── UserAuthMethods.json
│       │   ├── DirectoryRoles.json
│       │   ├── PIMAssignments.json
│       │   ├── ConditionalAccessPolicies.json
│       │   ├── Applications.json
│       │   ├── ServicePrincipals.json
│       │   ├── ManagedDevices.json
│       │   ├── RiskyUsers.json
│       │   ├── RiskDetections.json
│       │   ├── SecurityDefaults.json
│       │   ├── DirectoryAuditLogs.json
│       │   └── SignInLogs.json
│       └── TenantB_Fabrikam/
│           └── ... (similar files)
└── Reports/
    └── ... (final report outputs)
```

*   **File Naming:** Simple, descriptive names corresponding to the data type (e.g., `Users.json`, `ConditionalAccessPolicies.json`).
*   **Format:** JSON will be used for its ease of parsing in PowerShell (`Import-Json`, `ConvertTo-Json`) and human readability.

## 3. Extraction Logic Changes (`Start-CSPReporting.ps1`)

The core data extraction loop within `Start-CSPReporting.ps1` (around lines 395-425) will be modified to incorporate caching logic.

For *each* data extraction step (e.g., fetching Users, fetching Directory Roles):

1.  **Determine Cache File Path:** Construct the full path to the expected raw data cache file based on the current date, tenant name, and extraction type (e.g., `$cacheFilePath = Join-Path $outputPath "_Cache" $runDate $tenantName "Users.json"`).
2.  **Check for Cache Hit (Resume/Idempotency):**
    *   Evaluate if cached data should be used. This is true if:
        *   The `-Resume` switch is used OR it's not the first execution attempt for this tenant/step today (requires state tracking - see Section 4).
        *   AND the `-ForceFresh` switch (see Section 5) is *not* used.
        *   AND the cache file (`$cacheFilePath`) exists.
    *   If a cache hit occurs:
        *   Log a message (INFO level): `Loading cached Users data for TenantName from $cacheFilePath`.
        *   Load the data: `$tenantRawData.Users = Get-Content -Path $cacheFilePath | ConvertFrom-Json`. Handle potential file read/JSON parse errors gracefully.
        *   Skip the corresponding `Get-CSP...` API call.
3.  **Perform Live Extraction (Cache Miss or Force Fresh):**
    *   If no cache hit (file doesn't exist, or `-ForceFresh` is used):
        *   Log a message (INFO level): `Extracting live Users data for TenantName...`.
        *   Call the appropriate extraction function: `$extractedData = Get-CSPUserData`.
        *   **Handle Extraction Function Errors/Skips:** Check if the function returned valid data or indicated a skip (e.g., due to licensing for PIM).
        *   If data was successfully extracted:
            *   Assign it: `$tenantRawData.Users = $extractedData`.
            *   **Save to Cache:**
                *   Ensure the cache directory exists (`New-Item -ItemType Directory -Force`).
                *   Save the data: `$extractedData | ConvertTo-Json -Depth 10 | Out-File -FilePath $cacheFilePath -Encoding UTF8`. Handle potential file write errors.
                *   Log a message (INFO level): `Saved extracted Users data for TenantName to $cacheFilePath`.
        *   If the extraction function indicated a skip (e.g., PIM license missing):
            *   Log the reason (WARNING level).
            *   Assign an appropriate marker: `$tenantRawData.PIMAssignments = @{ SkippedReason = 'License missing' }`.
            *   Optionally, save this marker to the cache file as well, so the skip is remembered on resume.

This check-load-or-extract-save pattern needs to be applied individually to *every* `Get-CSP...` call within the v2 data extraction block.

## 4. State Management Updates (`StateManagement.psm1` & `Start-CSPReporting.ps1`)

While the file existence check provides basic resumability, enhancing the state file adds robustness and clarity.

*   **Modified State Structure:** The data stored per tenant in the state file (`CSPReporting_State.xml` or similar) should be enhanced to track the completion of individual extraction steps.

    ```xml
    <!-- Example State Structure -->
    <TenantState TenantId="tenant1-id" TenantName="TenantA_Contoso" Status="InProgress">
      <LastUpdateTime>2025-04-11T09:30:00Z</LastUpdateTime>
      <CompletedExtractions>
        <Extraction>TenantInfo</Extraction>
        <Extraction>DomainInfo</Extraction>
        <Extraction>Users</Extraction>
        <!-- Add more as they complete -->
      </CompletedExtractions>
      <CurrentStep>UserAuthMethods</CurrentStep> <!-- Optional: Track exact step -->
      <Error />
    </TenantState>
    ```

*   **`Update-CSPProcessState`:** Modify this function to accept an optional parameter like `-ExtractionCompleted` to add an entry to the `CompletedExtractions` list for the specified tenant.
*   **`Start-CSPReporting.ps1` Integration:**
    *   After successfully extracting *and saving* data for a step (e.g., Users), call `Update-CSPProcessState -TenantId ... -ExtractionCompleted "Users"`.
    *   The logic in Section 3 ("Check for Cache Hit") can optionally consult the state file (`Get-CSPProcessState`) in addition to `Test-Path` on the cache file to determine if a step was previously completed successfully. This adds resilience if a cache file was somehow deleted but the state file remains.

## 5. Handling Daily Runs & Fresh Starts

*   **Date-Based Folders:** The `YYYY-MM-DD` folder structure automatically isolates daily runs. Data cached on `2025-04-11` will not be reused on `2025-04-12` unless explicitly configured otherwise (which is not the default goal here).
*   **`-ForceFresh` Parameter:**
    *   Add a new switch parameter `[switch]$ForceFresh` to `Start-CSPReporting.ps1`.
    *   Modify the "Check for Cache Hit" logic (Section 3) to bypass cache loading if `$ForceFresh` is present.
    *   When `-ForceFresh` is used, the script should still *save* the newly extracted data to the cache, overwriting any existing files for that day.

## 6. Configuration Options (`Config.psd1` - Optional)

Consider adding settings to `Config.psd1` for better control:

*   `CachingEnabled = $true`: A master switch to enable/disable the file caching mechanism.
*   `RawDataRetentionDays = 7`: Number of days to keep cached raw data folders before potential cleanup (cleanup script would be separate).

## 7. Implementation Considerations

*   **Error Handling:** Implement robust `try/catch` blocks around file I/O operations (reading/writing cache files, creating directories) and JSON parsing. Log errors clearly.
*   **Filesystem Paths:** Ensure tenant names are sanitized to create valid directory names (e.g., replace invalid characters like `:` or `/`). A helper function `Get-SanitizedTenantName` might be useful.
*   **Performance:** Writing many small JSON files might have a minor performance overhead compared to keeping everything in memory, but this is negligible compared to the time saved by avoiding redundant API calls, especially for large tenants or slow connections.
*   **Analysis Step (`Invoke-CSPTenantAnalysis`):** This function needs to be updated. Instead of receiving a single large `$tenantRawData` hashtable, it might need to:
    *   Accept the path to the tenant's daily cache directory.
    *   Load the individual JSON files itself as needed for its analysis rules.
    *   Alternatively, the main script can still load all cached/extracted data into the `$tenantRawData` hashtable before calling the analysis function, maintaining the current interface. The latter is likely simpler initially.

This design provides a robust mechanism for making the data extraction process significantly more resilient and efficient for daily, multi-tenant reporting scenarios.