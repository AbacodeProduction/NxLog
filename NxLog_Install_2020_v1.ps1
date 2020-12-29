Param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")]
    [String]$SensorIP
    )

# Output the IPv4 address entered.
Write-Output -NoNewLine "Sensor IP is: $($SensorIP)"

$bit= wmic os get osarchitecture

# Check if PowerShell is running in admin mode. If not in admin mode, stop the script.
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }


Function installagent{
        if ($bit -like "64*") {

	                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

	                #Download and install NXLog CE
                    'Installing...'
	                 $WebClient = New-Object System.Net.WebClient

	                 #Download file for NXLOG MSI to user's desktop directory
	                 $WebClient.DownloadFile("https://nxlog.co/system/files/products/files/348/nxlog-ce-2.10.2150.msi","$env:USERPROFILE\Desktop\nxlog.msi")

	                 #Download file for nxlog config to user's desktop directory
	                 $WebClient.DownloadFile("https://cybersecurity.att.com/documentation/resources/downloads/usm-anywhere/nxlog.conf","$env:USERPROFILE\Desktop\nxlog.conf")

	                 #Install NXLOG MSI on Windows
	                    msiexec /i "$env:USERPROFILE\Desktop\nxlog.msi" /quiet /passive
	                    #Wait for Installation to complete
	                    Start-Sleep -s 10

	                    #replace the usmsensoriphere for IP of Sensor
	                    'Adding Sensor IP into conf file...'
	                    $USMip = $SensorIP
	                    $path = "$env:USERPROFILE\Desktop\nxlog.conf"
	
                        #Set the sensor IP
	                    $(Get-Content $path) | ForEach-Object { $_ -replace "usmsensoriphere", $USMip } | Set-Content $path
                        $(Get-Content $path) -replace "usmsensoriphere", $USMip | Set-Content $path
	                    #Copy the conf file to the NXLog system folder
	                    'Copying file to NXLog directory...'
                        $dest="$env:ProgramFiles (x86)\nxlog\conf\nxlog.conf"
	                    Copy-Item -Path $path -Destination $dest -force -Confirm:$false
    
                        #Cleaning up files from user's desktop
                        'Removing msi and conf files from users Desktop...'
                        Remove-Item $env:USERPROFILE\Desktop\nxlog.msi
                        Remove-Item $env:USERPROFILE\Desktop\nxlog.conf
                    }# end of TRUE IF



        else {"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

	                #Download and install NXLog CE
                    'Installing...'
	                 $WebClient = New-Object System.Net.WebClient

	                 #Download file for NXLOG MSI to user's desktop directory
	                 $WebClient.DownloadFile("https://nxlog.co/system/files/products/files/348/nxlog-ce-2.10.2150.msi","$env:USERPROFILE\Desktop\nxlog.msi")

	                 #Download file for nxlog config to user's desktop directory
	                 $WebClient.DownloadFile("https://cybersecurity.att.com/documentation/resources/downloads/usm-anywhere/nxlog.conf","$env:USERPROFILE\Desktop\nxlog.conf")

	                 #Install NXLOG MSI on Windows
	                    msiexec /i "$env:USERPROFILE\Desktop\nxlog.msi" /quiet /passive
	                    #Wait for Installation to complete
	                    Start-Sleep -s 10

	                    #replace the usmsensoriphere for IP of Sensor
	                    'Adding Sensor IP into conf file...'
	                    $USMip = $SensorIP
	                    $path = "$env:USERPROFILE\Desktop\nxlog.conf"
	
                        #Set the sensor IP
	                    $(Get-Content $path) | ForEach-Object { $_ -replace "usmsensoriphere", $USMip } | Set-Content $path
                        $(Get-Content $path) -replace "usmsensoriphere", $USMip | Set-Content $path
	                    #Copy the conf file to the NXLog system folder
	                    'Copying file to NXLog directory...'
                        $dest="$env:ProgramFiles\nxlog\conf\nxlog.conf"
	                    Copy-Item -Path $path -Destination $dest -force -Confirm:$false
    
                        #Cleaning up files from user's desktop
                        'Removing msi and conf files from users Desktop...'
                        Remove-Item $env:USERPROFILE\Desktop\nxlog.msi
                        Remove-Item $env:USERPROFILE\Desktop\nxlog.conf"}
        }

Function startagent{
	    'Starting service...'
	     #Check if NxLog is installed
	     $Service = Get-Service -Name "nxlog" -ErrorAction SilentlyContinue
		          If (-Not $Service) {
		            "NxLog is not installed on this server."
		          }else{
			            #Start nxlog service
			            Start-Service -Name nxlog
			            'NxLog started.'
		            }
	       sleep -s 5
                    }# end of startagent




installagent


#Declare counter to 0, used for exiting after failing 5 times
$counter = 0

# Attempt to start the agent if not started. If the service is running, exit the loop. 
# After 5 attempts, the powershell scripts exits.
do{
        #Check if the agent has been installed
        Restart-Service nxlog
        startagent

        #Check Status of Service. Continue to check until the service is running.
        $ServiceCheck = Get-Service -display nxlog -ErrorAction SilentlyContinue

        #Increment counter by 1
        $counter++
}until(($ServiceCheck.Status -eq 'Running') -or ($counter -eq 10))
### End of Script ###
            