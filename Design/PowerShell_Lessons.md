# Practical PowerShell Scripting Lessons Learned

## Introduction

This document captures key lessons learned during the development and debugging of the CSP Reporting v2 PowerShell framework. Adhering to these practices can help prevent common errors, improve code robustness, and make scripts easier to maintain.

## Lesson 1: Variable Scoping is Crucial

*   **Problem:** Unexpected variable values, errors like "variable is null" or incorrect API calls due to global variable conflicts overwriting function-local variables.
*   **Incorrect:**
    *   Relying on implicit scoping, potentially modifying global variables unintentionally.
    *   Using `$local:var` incorrectly (it refers to an *existing* local variable, doesn't reliably create one or shadow globals in all scenarios).
*   **Correct:**
    *   **Explicitly declare variables within function scope using type constraints** (e.g., `[string]$myVar = ...`, `[hashtable]$results = @{}`). This ensures the variable is truly local and correctly shadows any global variables with the same name.
    *   Use unique, descriptive variable names where necessary to avoid confusion, especially for commonly used names like `$url` or `$data`.
*   **Example:**

    ```powershell
    # Incorrect (might accidentally use or modify a global $apiUrl)
    function Invoke-MyApi {
        $apiUrl = "https://api.example.com/endpoint"
        # ... rest of code ...
        Invoke-RestMethod -Uri $apiUrl
    }

    # Correct (guarantees $apiUrl is local to this function)
    function Invoke-MyApi {
        [string]$apiUrl = "https://api.example.com/endpoint"
        # ... rest of code ...
        Invoke-RestMethod -Uri $apiUrl
    }
    ```

## Lesson 2: Careful URL Construction & Query Strings

*   **Problem:** Malformed API request URLs leading to "BadRequest" errors (e.g., missing path segments like `/v1.0/users`, incorrect query parameters, invalid characters).
*   **Incorrect:**
    *   Building URLs incrementally across different scopes where variables might be overwritten.
    *   Incorrectly escaping characters in query strings or using invalid characters.
*   **Correct:**
    *   Build the full URL string within the function scope using locally declared variables.
    *   Pay close attention to required query string syntax (`?` to start, `&` to separate parameters, parameter names like `$select=`, `$filter=`, `$count=true`).
    *   Use `[System.Web.HttpUtility]::UrlEncode()` for dynamic filter values or other parameters that might contain special characters.
*   **Example:**

    ```powershell
    # Incorrect (missing path, potential issues with $filter)
    $select = "id,displayName"
    $filter = "startswith(displayName, 'Test')"
    $url = "https://graph.microsoft.com/?$select=$select&$filter=$filter" # Missing /v1.0/users

    # Correct
    [string]$baseUrl = "https://graph.microsoft.com/v1.0/users"
    [string]$selectQuery = '$select=id,displayName'
    [string]$filterValue = "startswith(displayName, 'Test')"
    [string]$filterQuery = '$filter=' + [System.Web.HttpUtility]::UrlEncode($filterValue)
    [string]$apiUrl = "$baseUrl`?$selectQuery&$filterQuery" # Note: Only `?` needs escaping with backtick
    ```

## Lesson 3: PowerShell String Interpolation Quirks

*   **Problem:** Malformed strings, especially URLs, due to misunderstanding how backticks (`` ` ``) and dollar signs (`$`) work in double-quoted strings (`"`).
*   **Incorrect:**
    *   Unnecessary escaping (e.g., `` `$variable `` inside a string when just `$variable` works).
    *   Incorrect escaping (e.g., using `\` instead of `` ` ``).
    *   Using backticks where not needed (e.g., before `$select` or `$filter` in a query string: `?`$select=...` is wrong).
*   **Correct:**
    *   Understand that variables (`$var` or `${var}`) are automatically expanded in double-quoted strings.
    *   Use backticks (` `` `) *only* to escape literal characters that have special meaning within double quotes (`$`, `` ` ``, `"`), or to indicate line continuation.
    *   For query strings, typically only the initial `?` might need escaping (` ``?`` `) if used ambiguously, but standard OData parameters like `$select`, `$filter` etc., do *not* need the `$` escaped.
*   **Example:**

    ```powershell
    [string]$base = "https://graph.microsoft.com/v1.0/users"
    [string]$props = "id,displayName"
    [string]$count = '$count=true' # Use single quotes if $count is literal

    # Incorrect: Unnecessary backticks before $select, $count
    $url_bad = "$base`?`$select=$props&`$count=true"

    # Correct: Only escape the '?'
    $url_good = "$base`?$select=$props&$count"
    # Or using string formatting for clarity
    $url_fmt = '{0}?$select={1}&{2}' -f $base, $props, $count
    ```

## Lesson 4: Explicit Module Dependency Management

*   **Problem:** "Command not found" errors (`The term '...' is not recognized...`) even when the function exists in another `.psm1` file within the project.
*   **Incorrect:**
    *   Assuming functions from `Helper.psm1` are automatically available in `Main.psm1` just because they are in the same directory.
    *   Relying only on `Export-ModuleMember` in the helper module without an explicit `Import-Module` in the main module.
*   **Correct:**
    *   Modules need to explicitly import their dependencies using `Import-Module`. If `Main.psm1` uses functions from `Helper.psm1`, `Main.psm1` *must* contain `Import-Module -Name (Join-Path $PSScriptRoot 'Helper.psm1') -Force` (or similar path logic).
    *   The main script (`Start-CSPReporting.ps1` in our case) should import the top-level modules it directly interacts with. Those modules are then responsible for importing their own dependencies.
*   **Example (`Main.psm1`):**

    ```powershell
    # Main.psm1 - Needs functions from Helper.psm1

    # Correct: Explicitly import the dependency
    Import-Module -Name (Join-Path $PSScriptRoot 'Helper.psm1') -Force

    function Do-MainWork {
        # Now we can call functions defined and exported in Helper.psm1
        $helperResult = Get-HelperData -Param 'abc'
        Write-Output "Helper returned: $helperResult"
    }

    Export-ModuleMember -Function Do-MainWork
    ```

## Lesson 5: Effective Debugging with `Write-Verbose`

*   **Problem:** Difficulty diagnosing runtime errors without visibility into variable values or execution flow, especially with complex API calls or logic.
*   **Incorrect:**
    *   Using `Write-Host` for debugging (pollutes standard output, cannot be easily suppressed).
    *   Not having enough diagnostic points, making it hard to pinpoint where things go wrong.
*   **Correct:**
    *   Use `Write-Verbose "Message: $variable"` liberally within functions to output key variable values (like constructed URLs, API parameters, intermediate results) and trace execution steps.
    *   Ensure functions have `[CmdletBinding()]` to support common parameters like `-Verbose`.
    *   Run scripts with the `-Verbose` switch to activate this detailed output only when needed for debugging.
*   **Example:**

    ```powershell
    function Get-ApiData {
        [CmdletBinding()]
        param(
            [string]$Filter
        )

        [string]$baseUrl = "https://api.example.com/data"
        [string]$query = "?$filter=" + [System.Web.HttpUtility]::UrlEncode($Filter)
        [string]$apiUrl = $baseUrl + $query

        # Correct: Log the final URL before calling the API
        Write-Verbose "Requesting data from URL: $apiUrl"

        try {
            Invoke-RestMethod -Uri $apiUrl -Method Get
        } catch {
            Write-Error "API call failed: $($_.Exception.Message)"
        }
    }
    ```

## Conclusion

Writing robust PowerShell involves careful attention to variable scope, precise syntax (especially in strings and URLs), explicit dependency management between modules, and leveraging built-in debugging tools like `Write-Verbose`. Applying these lessons learned helps create more reliable, maintainable, and easier-to-debug automation scripts.