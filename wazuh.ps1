Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.5-1.msi" -OutFile "$env:TEMP\wazuh-agent.msi"
Start-Process msiexec.exe -ArgumentList "/i `"$env:TEMP\wazuh-agent.msi`" /qn WAZUH_MANAGER=172.23.150.42 WAZUH_REGISTRATION_SERVER=172.23.150.42" -Wait
NET START WazuhSvc
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
# PowerShell script to download, extract, and install Sysmon

# Set variables
$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$downloadPath = "$env:TEMP\Sysmon.zip"
$extractPath  = "$env:TEMP\Sysmon"
$configUrl    = "https://raw.githubusercontent.com/theunderpreparedtraveller/Wazuh-Sysmon-Custom-Rules/refs/heads/main/sys.xml"
$configPath   = "$env:TEMP\sysmonconfig.xml"

Write-Host "[*] Downloading Sysmon..."
Invoke-WebRequest -Uri $sysmonUrl -OutFile $downloadPath

Write-Host "[*] Extracting Sysmon..."
Expand-Archive -Path $downloadPath -DestinationPath $extractPath -Force

Write-Host "[*] Downloading default Sysmon config..."
Invoke-WebRequest -Uri $configUrl -OutFile $configPath

# Find Sysmon executable (x64 preferred)
$sysmonExe = Get-ChildItem -Path $extractPath -Recurse -Filter "Sysmon64.exe" | Select-Object -First 1

if (-Not $sysmonExe) {
    Write-Host "[!] Could not find Sysmon executable!"
    exit 1
}

Write-Host "[*] Installing Sysmon service..."
Start-Process -FilePath $sysmonExe.FullName -ArgumentList "-accepteula -i `"$configPath`"" -Wait -Verb RunAs

Write-Host "[+] Sysmon installed successfully!"
wevtutil set-log Microsoft-Windows-DNS-Client/Operational /enabled:true
wevtutil set-log Microsoft-Windows-TaskScheduler/Operational /enabled:true