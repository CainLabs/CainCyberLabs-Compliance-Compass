# CainCyberLabs PCI DSS Auditor v1.0 🛡️

A read-only PowerShell script designed to help system administrators and security professionals quickly audit their Windows systems against key technical controls from the PCI DSS v4.0 standard.

This tool is built to be non-intrusive, performing a series of checks and producing a clear, actionable report without making any changes to the target system.

## Key Features

* **System Configuration Auditing:** Checks for insecure services (Telnet, FTP) and outdated protocols (SMBv1).
* **Authentication Policy Auditing:** Verifies domain and local authentication policies (password length, complexity, lockout).
* **Advanced Policy Detection:** Detects the presence of Fine-Grained Password Policies (FGPPs) in Active Directory.
* **OS-Aware Logic:** Intelligently detects the OS type (Server vs. Client) to run only relevant checks.
* **Professional Reporting:** Produces a detailed, easy-to-read audit report in CSV format.

## How to Use

### Prerequisites

1.  The target machine must be running **Windows PowerShell 5.1** or later.
2.  The script must be run from an **elevated (Administrator)** PowerShell prompt.

### Execution

Copy the `CainCyberLabsAuditor.ps1` script to the machine you wish to audit. Open PowerShell as an Administrator, navigate to the script's directory, and run one of the following commands:

**To audit a standalone server or workstation:**
```powershell
.\CainCyberLabsAuditor.ps1 -Mode StandaloneServer -Verbose
