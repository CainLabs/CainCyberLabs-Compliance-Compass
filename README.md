-----
# Compliance Compass v1.0 by CainCyberLabs 🛡️

Compliance Compass is a read-only PowerShell script designed to help system administrators and security professionals quickly audit their Windows systems against key technical controls from the PCI DSS v4.0 standard.

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

Copy the `ComplianceCompass.ps1` script to the machine you wish to audit. Open PowerShell as an Administrator, navigate to the script's directory, and run one of the following commands:

**To audit a standalone server or workstation:**

```powershell
.\ComplianceCompass.ps1 -Mode StandaloneServer -Verbose
```

**To audit a Domain Controller:**

```powershell
.\ComplianceCompass.ps1 -Mode DomainController -Verbose
```

## Understanding the Report

The script generates a CSV report with the following columns:

  * **CheckID:** A unique identifier for the audit check.
  * **Description:** A plain-English description of the check being performed.
  * **Status:** The result of the check (PASS, FAIL, SKIPPED, INFO, ERROR).
  * **CurrentValue:** The actual setting found on the target system.
  * **ExpectedValue:** The desired setting for compliance.
  * **Remediation:** A brief, actionable suggestion for how to fix a failing check.
---
## The Audit Process Explained



When you run the script, here is exactly what it does, step-by-step:



1.  *Initialization:* The script begins and displays a green "Starting..." message, confirming the target machine and the audit mode (`StandaloneServer` or `DomainController`) you selected.



2.  *System Feature Checks:* The script calls the `Test-SystemFeatures` function.



    2.1. It first determines if the target is a Client or Server OS.

    2.2. It then checks for the installation of the insecure *Telnet Server* and *FTP Server* features (these checks are automatically skipped with a "SKIPPED" status if run on a client OS).

    2.3. Finally, it checks if the insecure *SMBv1* protocol is enabled.



3.  *Authentication Policy Checks:* The script then calls the `Test-AuthenticationPolicies` function.



    3.1. If in `StandaloneServer`, it audits the local security policies by checking the `net accounts` output for minimum password length and `Get-LocalUser` for the Administrator account's password expiration setting.

    3.2. If in `DomainController` mode, it audits the Active Directory Default Domain Policy. It checks for password complexity, minimum password length, and the account lockout threshold. It also performs an informational check to see if any Fine-Grained Password Policies exist.



4.  *Report Generation:* The script gathers the results from all the checks it performed into a single collection. Each result contains a Check ID, Description, Status (PASS, FAIL, SKIPPED, or INFO), and other details.



5.  *Completion:* The script exports the full collection of results to a new CSV file in the same directory (unless a custom path was specified). The file is named with the current date and time (e.g., `CainCyberLabs\_Audit\_20250924\_132300.csv`). A final green "Audit complete." message is displayed on your screen.


## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact

For support, premium features, or consulting inquiries, please contact: `[Your Future Business Email Address]`
