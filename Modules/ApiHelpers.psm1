<#
.SYNOPSIS
    API helper functions (e.g., retry logic) for CSP Reporting.
#>

function Invoke-CSPWithRetry {
    <#
    .SYNOPSIS
        Invokes a command with retry logic.
    .DESCRIPTION
        Invokes a command with retry logic for handling transient errors and rate limiting.
    .PARAMETER ScriptBlock
        The script block to invoke.
    .PARAMETER MaxRetries
        The maximum number of retry attempts.
    .PARAMETER RetryDelaySeconds
        The delay between retry attempts in seconds.
    .PARAMETER RetryStatusCodes
        HTTP status codes that should trigger a retry.
    .PARAMETER ActivityName
        The name of the activity for progress reporting.
    .EXAMPLE
        Invoke-CSPWithRetry -ScriptBlock { Get-MgUser -UserId "user@contoso.com" } -MaxRetries 3 -RetryDelaySeconds 2
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,
        
        [Parameter(Mandatory = $false)]
        [int]$RetryDelaySeconds = 2,
        
        [Parameter(Mandatory = $false)]
        [int[]]$RetryStatusCodes = @(429, 503, 504),
        
        [Parameter(Mandatory = $false)]
        [string]$ActivityName = "API Operation",
        
        [Parameter(Mandatory = $false)]
        [object]$ArgumentList
    )
    
    try {
        $retryCount = 0
        $success = $false
        $result = $null
        $lastError = $null
        
        while (-not $success -and $retryCount -le $MaxRetries) {
            try {
                if ($retryCount -gt 0) {
                    Write-CSPLog -Message "Retry attempt $retryCount of $MaxRetries for $ActivityName" -Level "INFO"
                    
                    # Progressive back-off for retries
                    $delay = $RetryDelaySeconds * [Math]::Pow(2, $retryCount - 1)
                    Write-CSPLog -Message "Waiting $delay seconds before retry..." -Level "INFO"
                    Start-Sleep -Seconds $delay
                }
                
                # Execute the command
                if ($ArgumentList) {
                    $result = & $ScriptBlock $ArgumentList
                } else {
                    $result = & $ScriptBlock
                }
                $success = $true
            }
            catch {
                $lastError = $_
                
                # Check if the error is due to rate limiting or a transient error
                $statusCode = $null
                
                # Try to extract status code from different exception types
                if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }
                elseif ($_.Exception.Message -match "Response status code does not indicate success: (\d+)") {
                    $statusCode = [int]$Matches[1]
                }
                
                if ($statusCode -and $RetryStatusCodes -contains $statusCode) {
                    $retryCount++
                    
                    # For 429 (Too Many Requests), check for Retry-After header
                    if ($statusCode -eq 429 -and $_.Exception.Response.Headers["Retry-After"]) {
                        $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"]
                        Write-CSPLog -Message "Rate limit hit. Retry-After header suggests waiting $retryAfter seconds." -Level "WARNING"
                        Start-Sleep -Seconds $retryAfter
                    }
                    
                    Write-CSPLog -Message "Transient error (Status Code: $statusCode) in $ActivityName. Retrying..." -Level "WARNING"
                }
                else {
                    # Non-retryable error
                    $errorMessage = $_.Exception.Message
                    Write-CSPLog -Message "Non-retryable error in $ActivityName. Error: $errorMessage" -Level "ERROR"
                    throw
                }
            }
        }
        
        if (-not $success) {
            Write-CSPLog -Message "Failed after $MaxRetries retry attempts: $lastError" -Level "ERROR"
            throw $lastError
        }
        
        return $result
    }
    catch {
        Write-Error "Error in Invoke-CSPWithRetry: $_"
        throw
    }
}

Export-ModuleMember -Function Invoke-CSPWithRetry