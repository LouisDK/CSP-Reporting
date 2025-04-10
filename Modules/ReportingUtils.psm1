<#
.SYNOPSIS
    Reporting utility functions (export, formatting) for CSP Reporting.
#>

function Export-CSPReportData {
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
        if (-not (Test-Path -Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        switch ($OutputFormat) {
            "CSV" {
                $csvPath = Join-Path -Path $OutputPath -ChildPath "$FileName.csv"
                $Data | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            }
            "JSON" {
                $jsonPath = Join-Path -Path $OutputPath -ChildPath "$FileName.json"
                $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
            }
            "Both" {
                $csvPath = Join-Path -Path $OutputPath -ChildPath "$FileName.csv"
                $Data | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                $jsonPath = Join-Path -Path $OutputPath -ChildPath "$FileName.json"
                $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
            }
        }
        return $true
    } catch {
        Write-Error "Error in Export-CSPReportData: $_"
        return $false
    }
}

function Format-CSPReportFileName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ReportType,
        [Parameter(Mandatory = $true)]
        [string]$TenantName
    )
    try {
        $dateStamp = Get-Date -Format "yyyyMMdd"
        return "${ReportType}_${TenantName}_${dateStamp}"
    } catch {
        Write-Error "Error in Format-CSPReportFileName: $_"
        return "Error_${ReportType}_${TenantName}"
    }
}

Export-ModuleMember -Function Export-CSPReportData, Format-CSPReportFileName