<#
.SYNOPSIS
    A read-only security auditor for PCI DSS technical controls.
.DESCRIPTION
    The CainCyberLabs Auditor checks a system for compliance against a defined set of PCI DSS controls
    for system features and authentication policies.
.AUTHOR
    CainCyberLabs, LLC
.VERSION
    1.0.0
.PARAMETER ComputerName
    The target computer to audit.
.PARAMETER Mode
    The audit mode: 'DomainController' or 'StandaloneServer'.
.PARAMETER ReportPath
    The full path to save the CSV audit report.
.EXAMPLE
    .\CainCyberLabsAuditor.ps1 -ComputerName 'DC01' -Mode 'DomainController' -ReportPath 'C:\audits\DC01_audit.csv'
#>
param (
    [string]$ComputerName = $env:COMPUTERNAME,
    [ValidateSet('DomainController', 'StandaloneServer')]
    [string]$Mode = 'StandaloneServer',
    [string]$ReportPath = ".\CainCyberLabs_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

# --- FUNCTION DEFINITIONS ---

function Test-SystemFeatures {
    param (
        [string]$ComputerName
    )

    $Results = @()
    $Session = $null
    try {
        $Session = New-PSSession -ComputerName $ComputerName -ErrorAction Stop

        if ($Session) {
            $osInfo = Invoke-Command -Session $Session -ScriptBlock { Get-CimInstance Win32_OperatingSystem }

            if ($osInfo.ProductType -ne 1) { # Server OS
                # Telnet Check
                $feature = Invoke-Command -Session $Session -ScriptBlock { Get-WindowsFeature -Name Telnet-Server }
                if ($feature.Installed) { $telnetStatus = "FAIL"; $telnetCurrentValue = "Installed" } else { $telnetStatus = "PASS"; $telnetCurrentValue = "Not Installed" }
                $Results += [PSCustomObject]@{ CheckID = "PCI-2.2.4-Telnet"; Description = "Insecure Telnet Server feature is installed"; Status = $telnetStatus; CurrentValue = $telnetCurrentValue; ExpectedValue = "Not Installed"; Remediation = "Uninstall the Telnet-Server feature." }

                # FTP Check
                $feature = Invoke-Command -Session $Session -ScriptBlock { Get-WindowsFeature -Name Web-Ftp-Server }
                if ($feature.Installed) { $ftpStatus = "FAIL"; $ftpCurrentValue = "Installed" } else { $ftpStatus = "PASS"; $ftpCurrentValue = "Not Installed" }
                $Results += [PSCustomObject]@{ CheckID = "PCI-2.2.4-FTP"; Description = "Insecure FTP Server feature is installed"; Status = $ftpStatus; CurrentValue = $ftpCurrentValue; ExpectedValue = "Not Installed"; Remediation = "Uninstall the Web-Ftp-Server feature." }

            } else { # Client OS
                $Results += [PSCustomObject]@{ CheckID = "PCI-2.2.4-Telnet"; Description = "Insecure Telnet Server feature is installed"; Status = "SKIPPED"; CurrentValue = "Target is a client OS"; ExpectedValue = "N/A"; Remediation = "This check only applies to Windows Server." }
                $Results += [PSCustomObject]@{ CheckID = "PCI-2.2.4-FTP"; Description = "Insecure FTP Server feature is installed"; Status = "SKIPPED"; CurrentValue = "Target is a client OS"; ExpectedValue = "N/A"; Remediation = "This check only applies to Windows Server." }
            }

            # SMBv1 Check
            $smbConfig = Invoke-Command -Session $Session -ScriptBlock { Get-SmbServerConfiguration }
            if ($smbConfig.EnableSMB1Protocol) { $smb1Status = "FAIL"; $smb1CurrentValue = "Enabled" } else { $smb1Status = "PASS"; $smb1CurrentValue = "Disabled" }
            $Results += [PSCustomObject]@{ CheckID = "PCI-2.2.4-SMBv1"; Description = "Insecure SMBv1 protocol is enabled"; Status = $smb1Status; CurrentValue = $smb1CurrentValue; ExpectedValue = "Disabled"; Remediation = "Disable SMBv1 using Set-SmbServerConfiguration." }
        
        } else {
            throw "Failed to create a PSSession."
        }
    }
    catch {
        $Results += [PSCustomObject]@{ CheckID = "Connectivity"; Description = "Failed to connect or execute remote commands in Test-SystemFeatures"; Status = "ERROR"; CurrentValue = $_.Exception.Message; ExpectedValue = "Successful Connection"; Remediation = "Ensure PowerShell Remoting (WinRM) is enabled, TrustedHosts is configured, and you are running as Administrator." }
    }
    finally {
        if ($Session) { Remove-PSSession -Session $Session }
    }
    return $Results
}

function Test-AuthenticationPolicies {
    param (
        [string]$ComputerName,
        [string]$Mode
    )
    $Results = @()
    $Session = $null
    try {
        $Session = New-PSSession -ComputerName $ComputerName -ErrorAction Stop
        
        if ($Session) {
            if ($Mode -eq 'DomainController') {
                $policy = Invoke-Command -Session $Session -ScriptBlock { Get-ADDefaultDomainPasswordPolicy }
                
                # DC Checks
                if ($policy.PasswordComplexityEnabled) { $status = "PASS"; $currentValue = "Enabled" } else { $status = "FAIL"; $currentValue = "Disabled" }
                $Results += [PSCustomObject]@{ CheckID = "PCI-8.2.3-Complexity"; Description = "Password complexity is enabled for the domain"; Status = $status; CurrentValue = $currentValue; ExpectedValue = "Enabled"; Remediation = "Enable password complexity in the Default Domain Policy GPO." }

                if ($policy.MinPasswordLength -ge 12) { $status = "PASS" } else { $status = "FAIL" }
                $Results += [PSCustomObject]@{ CheckID = "PCI-8.2.3-Length"; Description = "Minimum password length is 12 characters or more"; Status = $status; CurrentValue = $policy.MinPasswordLength; ExpectedValue = "12 or greater"; Remediation = "Set minimum password length to 12 or more in the Default Domain Policy GPO." }

                if ($policy.LockoutThreshold -gt 0 -and $policy.LockoutThreshold -le 10) { $status = "PASS" } else { $status = "FAIL" }
                $Results += [PSCustomObject]@{ CheckID = "PCI-8.2.4-Lockout"; Description = "Account lockout is enabled and set to a reasonable threshold"; Status = $status; CurrentValue = $policy.LockoutThreshold; ExpectedValue = "Between 1 and 10"; Remediation = "Set the account lockout threshold to a value between 1 and 10 in the GPO." }
                
                $fgpps = Invoke-Command -Session $Session -ScriptBlock { Get-ADFineGrainedPasswordPolicy -Filter * }
                $Results += [PSCustomObject]@{ CheckID = "PCI-8.2.3-FGPP"; Description = "Check for existence of Fine-Grained Password Policies"; Status = "INFO"; CurrentValue = "Found $($fgpps.Count) policies"; ExpectedValue = "N/A"; Remediation = "Manually review any existing FGPPs to ensure they meet or exceed domain policy." }

            } elseif ($Mode -eq 'StandaloneServer') {
                # Standalone Checks
                $netAccounts = Invoke-Command -Session $Session -ScriptBlock { net accounts }
                $minLengthLine = $netAccounts | Select-String -Pattern "Minimum password length"
                $currentLength = ($minLengthLine -split '\s+')[-1]
                if ([int]$currentLength -ge 12) { $status = "PASS" } else { $status = "FAIL" }
                $Results += [PSCustomObject]@{ CheckID = "PCI-8.2.3-LocalLength"; Description = "Local minimum password length is 12 characters or more"; Status = $status; CurrentValue = $currentLength; ExpectedValue = "12 or greater"; Remediation = "Set local minimum password length using 'net accounts /minpwlen:12'." }

                $localAdmin = Invoke-Command -Session $Session -ScriptBlock { Get-LocalUser -Name "Administrator" }
                if ($localAdmin.PasswordNeverExpires) { $status = "FAIL"; $currentValue = "Enabled" } else { $status = "PASS"; $currentValue = "Disabled" }
                $Results += [PSCustomObject]@{ CheckID = "PCI-8.2.4-AdminExpire"; Description = "Local Administrator account password is configured to expire"; Status = $status; CurrentValue = $currentValue; ExpectedValue = "Disabled"; Remediation = "Configure the built-in Administrator account password to expire." }
            }
        } else {
            throw "Failed to create a PSSession."
        }
    }
    catch {
        $Results += [PSCustomObject]@{ CheckID = "Connectivity"; Description = "Failed to connect or execute remote commands in Test-AuthenticationPolicies"; Status = "ERROR"; CurrentValue = $_.Exception.Message; ExpectedValue = "Successful Connection"; Remediation = "Ensure PowerShell Remoting (WinRM) is enabled, TrustedHosts is configured, and you are running as Administrator." }
    }
    finally {
        if ($Session) { Remove-PSSession -Session $Session }
    }
    return $Results
}


# --- MAIN EXECUTION ---

$allResults = @()
Write-Host "Starting CainCyberLabs Auditor on $ComputerName in $Mode mode..." -ForegroundColor Green

Write-Host "Running system feature checks..."
$allResults += Test-SystemFeatures -ComputerName $ComputerName

Write-Host "Running authentication policy checks..."
$allResults += Test-AuthenticationPolicies -ComputerName $ComputerName -Mode $Mode

Write-Host "Generating report at $ReportPath..."
$allResults | Export-Csv -Path $ReportPath -NoTypeInformation

Write-Host "Audit complete." -ForegroundColor Green