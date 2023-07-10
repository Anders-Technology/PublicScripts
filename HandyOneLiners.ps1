<#
A ist of 1-liners that I find handy that save me time.

Anywhere you see a variable (a word that starts with a $) you'll need to either replace the variable with the
real target, or define the variable to hit the target.
#>

#Check for a pending reboot
$rebootRequired = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
"Pending reboot: $rebootRequired" 

#Search Event Logs for text string
$string = "C:"
Get-EventLog -LogName system -after (Get-Date).AddDays(-1) | Where-Object { $_.Category.ToLower().Contains($string.ToLower()) -or $_.Message.ToLower().Contains($string.ToLower()) -or $_.Source.ToLower().Contains($string.ToLower())} | Format-Table -AutoSize -Wrap

#Repair domain trust relationship
Test-ComputerSecureChannel -Repair

#Get PC Uptime
Get-CimInstance -ClassName Win32_OperatingSystem | Select LastBootUpTime

#Rename PC & restart
Rename-Computer -NewName '$Variable' -DomainCredential '$Credential' -Restart

#Get local PC FQDN
[System.Net.Dns]::GetHostByName($env:computerName).HostName

#Get remote PC FQDN
[System.Net.Dns]::GetHostByName('$PCName').HostName

#Join a PC to local domain, rename it, and place it in a specific OU
Add-Computer -DomainName '$domain' -OUPath '$OUPath' -NewName '$NewName' -credential $Credential

#Use ps-remoting to connect to a different computer's powershell, then execute commands on that computer.
Enter-PSSession -ComputerName $ComputerName -Credential $Credential

#Via ps-remoting, execute commands on the remote server using -ScriptBlock
Invoke-Command -ComputerName $ServerName -Credential $credential -ScriptBlock{start-adsyncsynccycle}

#Disconnect from another PC's Powershell
Exit-PSSession

#Restart PC immediately, skipping Windows Update
Restart-Computer -Force

#Jiggle the mouse to prevent sleep [no worky for Teams status, but can keep PC awake]
Add-Type -assemblyName System.Windows.Forms;$a=@(1..100);while(1){[System.Windows.Forms.Cursor]::Position=New-Object System.Drawing.Point(($a|get-random),($a|get-random));start-sleep -seconds 5}

#Get list of installed software on 64-bit machine
Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize

#Get list of installed software on 32-bit machine
Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize