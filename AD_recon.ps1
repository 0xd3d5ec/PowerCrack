<#
.SYNOPSIS
    A comprehensive PowerShell script for local and Active Directory reconnaissance.

.DESCRIPTION
    This script performs a variety of checks on a local machine and an Active Directory
    environment to gather information for penetration testing purposes.

.AUTHOR
    Jules
#>

param(
    [string]$OutputFile,
    [switch]$Help
)

if ($Help) {
    Write-Host @"
.SYNOPSIS
    A comprehensive PowerShell script for local and Active Directory reconnaissance.

.DESCRIPTION
    This script performs a variety of checks on a local machine and an Active Directory
    environment to gather information for penetration testing purposes.

.PARAMETER <OutputFile>
    Specifies the file to write the output to.

.EXAMPLE
    PS> .\AD_recon.ps1 -OutputFile C:\temp\recon_results.txt
    This will run the script and save the output to C:\temp\recon_results.txt

.EXAMPLE
    PS> .\AD_recon.ps1 -Help
    This will display this help message.
"@
    exit
}

if ($PSBoundParameters.ContainsKey('OutputFile')) {
    Start-Transcript -Path $OutputFile -Force
}


# Script Start
Write-Host "Starting Reconnaissance Script" -ForegroundColor Yellow

# ======================================================================================================================
# Local Reconnaissance
# ======================================================================================================================

Write-Host "[+] Starting Local Reconnaissance" -ForegroundColor Green

# ----------------------------------------------------------------------------------------------------------------------
# System Information
# ----------------------------------------------------------------------------------------------------------------------
Write-Host "[*] Gathering System Information..." -ForegroundColor Cyan
Get-ComputerInfo | Out-String

# ----------------------------------------------------------------------------------------------------------------------
# User Information
# ----------------------------------------------------------------------------------------------------------------------
Write-Host "[*] Gathering User Information..." -ForegroundColor Cyan
Write-Host "Current User:"
whoami
Get-CimInstance -Class Win32_UserAccount -Filter "LocalAccount='True'" | Select-Object Name, SID, Status, Disabled, Lockout | Format-Table -AutoSize

Write-Host "Local Groups:"
Get-LocalGroup | Select-Object Name, Description | Format-Table -AutoSize

# ----------------------------------------------------------------------------------------------------------------------
# Network Information
# ----------------------------------------------------------------------------------------------------------------------
Write-Host "[*] Gathering Network Information..." -ForegroundColor Cyan
Get-NetIPAddress | Select-Object IPAddress, InterfaceAlias, AddressFamily | Format-Table -AutoSize
Get-NetRoute | Format-Table -AutoSize
Get-DnsClientCache | Format-Table -AutoSize

# ----------------------------------------------------------------------------------------------------------------------
# Running Processes and Services
# ----------------------------------------------------------------------------------------------------------------------
Write-Host "[*] Gathering Process and Service Information..." -ForegroundColor Cyan
Get-Process | Select-Object ProcessName, Id, CPU, Path | Format-Table -AutoSize
Get-Service | Where-Object { $_.State -eq "Running" } | Select-Object Name, DisplayName, Status | Format-Table -AutoSize

# ----------------------------------------------------------------------------------------------------------------------
# Installed Software
# ----------------------------------------------------------------------------------------------------------------------
Write-Host "[*] Gathering Installed Software..." -ForegroundColor Cyan
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize

# ----------------------------------------------------------------------------------------------------------------------
# PowerShell History
# ----------------------------------------------------------------------------------------------------------------------
Write-Host "[*] Gathering PowerShell History..." -ForegroundColor Cyan
Get-Content (Get-PSReadlineOption).HistorySavePath | Out-String


# ======================================================================================================================
# Active Directory Reconnaissance
# ======================================================================================================================

Write-Host "[+] Starting Active Directory Reconnaissance" -ForegroundColor Green

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Host "[-] ActiveDirectory module not found. Skipping AD recon." -ForegroundColor Red
    # Script End
    Write-Host "Reconnaissance Script Finished" -ForegroundColor Yellow
    exit
}

# ----------------------------------------------------------------------------------------------------------------------
# Domain Information
# ----------------------------------------------------------------------------------------------------------------------
Write-Host "[*] Gathering Domain Information..." -ForegroundColor Cyan
Get-ADDomain | Select-Object Name, DNSRoot, DomainControllersContainer, Forest, DomainMode | Format-Table -AutoSize
Get-ADForest | Format-Table -AutoSize

# ----------------------------------------------------------------------------------------------------------------------
# User and Group Information
# ----------------------------------------------------------------------------------------------------------------------
Write-Host "[*] Gathering Domain User and Group Information..." -ForegroundColor Cyan
Write-Host "Domain Admins:"
Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object name, samaccountname | Format-Table -AutoSize

Write-Host "All Domain Users:"
Get-ADUser -Filter * | Select-Object Name, SamAccountName, Enabled | Format-Table -AutoSize

# ----------------------------------------------------------------------------------------------------------------------
# Computer Objects
# ----------------------------------------------------------------------------------------------------------------------
Write-Host "[*] Gathering Computer Objects..." -ForegroundColor Cyan
Get-ADComputer -Filter * | Select-Object Name, DNSHostName, OperatingSystem | Format-Table -AutoSize

# ----------------------------------------------------------------------------------------------------------------------
# Group Policy Objects (GPOs)
# ----------------------------------------------------------------------------------------------------------------------
Write-Host "[*] Gathering GPO Information..." -ForegroundColor Cyan
Get-GPO -All | Select-Object DisplayName, Owner, GpoStatus | Format-Table -AutoSize

# ----------------------------------------------------------------------------------------------------------------------
# Kerberoastable Users
# ----------------------------------------------------------------------------------------------------------------------
Write-Host "[*] Searching for Kerberoastable Users..." -ForegroundColor Cyan
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | Select-Object Name, ServicePrincipalName | Format-Table -AutoSize

# ----------------------------------------------------------------------------------------------------------------------
# AS-REP Roastable Users
# ----------------------------------------------------------------------------------------------------------------------
Write-Host "[*] Searching for AS-REP Roastable Users..." -ForegroundColor Cyan
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Select-Object Name, SamAccountName | Format-Table -AutoSize


# Script End
Write-Host "Reconnaissance Script Finished" -ForegroundColor Yellow

if ($PSBoundParameters.ContainsKey('OutputFile')) {
    Stop-Transcript
}
