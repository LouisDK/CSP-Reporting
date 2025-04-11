<#
.SYNOPSIS
    PowerShell module management utilities for CSP Reporting.
#>

function Test-CSPModuleAvailability {
    <#
    .SYNOPSIS
        Tests if required modules are available.
    .DESCRIPTION
        Tests if required modules are available and installs them if necessary.
    .PARAMETER ModuleNames
        The names of the modules to check.
    .PARAMETER InstallIfMissing
        If specified, missing modules will be installed.
    .EXAMPLE
        Test-CSPModuleAvailability -ModuleNames "Microsoft.Graph", "Az.Accounts" -InstallIfMissing
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ModuleNames,
        
        [Parameter(Mandatory = $false)]
        [switch]$InstallIfMissing
    )
    
    try {
        $results = @()
        
        foreach ($moduleName in $ModuleNames) {
            $moduleAvailable = Get-Module -Name $moduleName -ListAvailable
            
            if ($moduleAvailable) {
                $results += [PSCustomObject]@{
                    ModuleName = $moduleName
                    Available = $true
                    Version = ($moduleAvailable | Sort-Object Version -Descending | Select-Object -First 1).Version
                    Installed = $false
                }
            }
            else {
                if ($InstallIfMissing) {
                    Write-Verbose "Installing module $moduleName"
                    Install-Module -Name $moduleName -Scope CurrentUser -Force
                    
                    $moduleAvailable = Get-Module -Name $moduleName -ListAvailable
                    
                    $results += [PSCustomObject]@{
                        ModuleName = $moduleName
                        Available = $true
                        Version = ($moduleAvailable | Sort-Object Version -Descending | Select-Object -First 1).Version
                        Installed = $true
                    }
                }
                else {
                    $results += [PSCustomObject]@{
                        ModuleName = $moduleName
                        Available = $false
                        Version = $null
                        Installed = $false
                    }
                }
            }
        }
        
        return $results
    }
    catch {
        Write-Error "Error in Test-CSPModuleAvailability: $_"
        return $null
    }
}


Export-ModuleMember -Function Test-CSPModuleAvailability