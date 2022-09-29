#stop dell optimizer services
Get-Service -Name "DellOptimizer" | Stop-Service



#Get Dell Optimizer from registry
$uninstallstring = get-itemproperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object { $_.DisplayName -match "optimizer service"}



#get the uninstall string for dell optimizer
$uninstallstring = $removeapp.UninstallString



#add the silent parameter and run throguh cmd to uninstall
cmd /c $uninstallstring -silent