#Requires -version 5 -Modules ServerManager, WebAdministration -RunAsAdministrator

# need a blank line below or Help will not display

 

[cmdletbinding()]

Param(

    [Parameter(Mandatory = $false, HelpMessage = "Required and must be one of the following: DEV, SYS, INT,ACC, PVS, REL,PRD, PFX, TRN, TPA")]

    [ValidateSet("DEV", "SYS", "INT", "ACC", "PVS", "REL", "PRD", "PFX", "TRN", "TPA")]

    [String]$Env = "DEV",

 

    [Parameter(Mandatory = $false, HelpMessage = "Reqiured and in format of LOB\WEBSITENAME\RELNUM\LOB_WEBSITENAME.xml")]

    [String]$PlayBookPath = "SYS\Demo\1\SYS_Demo_Rel1.2.xml",

    #    [String]$PlayBookPath ="SYS\DEMO\1\SYS_DEMO_Rel1.20.xml",

 

    [Parameter(Mandatory = $false, HelpMessage = "Required and must be an ID that has at least read access to \\CIWIIS0P0021\WebSiteAutomation")]

    [String]$PBLogon = "internal\mcbuck",

 

    [Parameter(Mandatory = $false, HelpMessage = "Required, Password for PBLogon. If blank will be prompted.")]

    [String]$PBPassword = "",

 

    [Parameter(Mandatory = $false, HelpMessage = "Required if Venafi switch is true and must be an ID that has at least read access to Venafi Hive in PlayBook")]

    [String]$VenafiLogon = "internal\mcbuck",

 

    [Parameter(Mandatory = $false, HelpMessage = "Required, Venafi Password for Venafi ID. If blank will be prompted.")]

    [String]$VenafiPassword = "",

 

    [Parameter(Mandatory = $false, HelpMessage = "a switch as -backup to force a backup before building new site")]

    [Switch]$BackUp = $false,

 

    [Parameter(Mandatory = $false, HelpMessage = "a switch as -Venafi to interact with Venafi to download cert it it  exists")]

    [Switch]$Venafi = $true,

 

    [Parameter(Mandatory = $false)]

    [switch]$Test = $false

)

###########################################################

$ScriptName = "NewSite2"

$ScriptVersion = "2019.06.25"

$ScriptAuthor = "Marshall Buck"

$ScriptRevised = "06/25/2019"

$ScriptCreated = "06/20/2017"

 

<#

 

.SYNOPSIS

    Reads the Application's XML PlayBook and builds a web site.

 

.DESCRIPTION

    Uses information supplied the the playbook to build a website for the on the

    logged on server based on the supplied environment.

 

.PARAMETER ENV

    Must be one of the following: "DEV", "SYS", "INT", "ACC", "PVS", "REL", "PRD", "PFX", "TPA", "TRN"

 

.PARAMETER PlayBookPath

    Path to the playbook  in format of LOB\WEBSITENAME\RELNUM\LOB_WEBSITENAME.VERSION.xml"

 

.PARAMETER PBLogon

    Logon Id with access to \\CIWIIS0P0021\WebSiteAutomation\PlayBooks

 

.PARAMETER PBPassword

    Password for Id with access to \\CIWIIS0P0021\WebSiteAutomation\PlayBooks

 

.PARAMETER BackUp

    True/False for whether to backup Metabase and Files before deleting old site

 

.PARAMETER Venafi

    True/False for whether to prompt for credentials for Venafi to try and download a certificate for this site

 

.PARAMETER Test

    True/False for whether to read playbook from TEST PlayBook Repository

 

.INPUTS

  XML PlayBook

 

.OUTPUTS

    Logs showing results of the web site Build

    Log file stored in \\CIWIIS0P0021\WebSiteAutomation\Logs\NewSite2\

    NewSite2_Cons_USEREXECUTING_ENVIRONMENT_SERVERNAME_YYYYMMDD-HH.MM.SS.MMM.log

    NewSite2_Err_USEREXECUTING_ENVIRONMENT_SERVERNAME_YYYYMMDD-HH.MM.SS.MMM.log

 

.NOTES

    $ScriptName = "NewSite2"

    $ScriptVersion = "2019.06.25"

    $ScriptAuthor = "Marshall Buck"

    $ScriptRevised = "06/25/2019"

    $ScriptCreated = "06/20/2017"

 

 

.EXAMPLE

    C:\scripts\IIS\NewSite2.ps1 -Env DEV -PlayBookPath SYS\Demo\1\SYS_Demo_Rel1.12.xml -PBLogon internal\mcbuc1 -PBPassword Password1 -Backup -Venafi

 

.LINK

    NewSite2_Backup.ps1

 

.LINK

    NewSite2_GetCert.ps1 - Pull cert down from Venafi is $Venafi switch is true

 

.LINK

    NewSite2_Settings - Set default security Settings

 

.LINK

    https://dev-developerportal.sys.cigna.com/WebSiteAutomation/

#>#>

Write-Host "Running: $($ScriptName) Ver: $($ScriptVersion) Written By: $($ScriptAuthor) On: $($ScriptCreated) Revised: $($ScriptRevised)"

$Global:Memory   = (Get-WMIObject win32_computersystem).TotalPhysicalMemory

$Global:MemoryGB = (Get-WMIObject win32_computersystem).TotalPhysicalMemory/1gb -as [int]

Write-Host "Memory on server in GB: $Global:MemoryGB In Bytes: $Global:Memory"

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

 

#SilentlyContinue - error messages are suppressed and execution continues.

#Stop - forces execution to stop, behaving like a terminating error.

#Continue the default option. Errors will display and execution will continue.

#Inquire - prompt the user for input to see if we should proceed.

#Ignore - (new in v3) the error is ignored and not logged to the error stream. Has very restricted usage scenarios.

 

#Set Error Action to Silently Continue

$ErrorActionPreference = "SilentlyContinue"

$ErrorActionPreference = "Continue"

 

#Dot Source required Function Libraries

#. "C:\TFS\Enterprise-WebHosting\PowerShellScripts\WebSiteAutomation\Trunk\WebSiteAutomation\WebSiteAutomation\WebSiteAutomation\Logging_Functions.ps1"

$error.clear()

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Log File Info

[string]$Global:TimeStamp = $(Get-Date -format yyyyMMdd-HH.mm.ss.fff)

[string]$Global:Location = "C:\Scripts\IIS"

#[string]$Global:PreviousVersion = $Global:Location + "\Previous_Version.ps1"

 

 

# Save Parms

[string]$Global:CurrentEnv = $ENV

[string]$Global:RequestedBy = $Parm_RequestedBy

[string]$Global:PBLogon = $PBLogon

[string]$Global:PBPassword = $PBPassword

[string]$Global:VenafiLogon = $VenafiLogon

[string]$Global:VenafiPassword = $VenafiPassword

$Global:PBCredential

$Global:VenafiCredential

[int]$TimeToSleep = 1 # Number of seconds to sleep to allow for slow CPC Servers

[int]$WindowsVersion = 0

$Memory = (Get-WMIObject win32_computersystem).TotalPhysicalMemory

# Processing Control Variables

[Boolean]$Global:Processing = $true

[boolean]$Global:CertificateFound = $false

[boolean]$Global:IsWebSiteAuthenticatioInfoSet = $false

[boolean]$Global:IsThereARootCA = $False

 

 

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

$Global:IsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

"Running as Administrator: $($Global:IsAdmin)"

# Default locations

[string]$Global:PhysicalServerName = $ENV:ComputerName

[string]$Global:PagesDrive = "E:"

[string]$Global:HostingDrive = "F:"

[string]$Global:LogsDrive = "F:"

 

# Server has single IP

[Boolean]$CPCServer = $False

[Boolean]$SingleIP = $False

 

if (($Global:PhysicalServerName.Substring(0, 8) -ieq "CIWCPCXD") `

        -or ($Global:PhysicalServerName.Substring(0, 8) -ieq "CIWSDBXD")) {

    $CPCServer = $True

}

[string]$Global:Domain = $env:USERDOMAIN

# Certificate fields

[string]$Global:ThumbPrint = ""

 

# Globals for Certs Owners

[string]$Global:ASGName

[string]$Global:HPSMAssignmentGroup

[string]$Global:ApplicationId

[string]$Global:TFSGroup

[string]$Global:VenafiHive

 

# Fields from PlayBook

[string]$Global:AppPool = ""

[string]$Global:LOB = ""

[string]$Global:Release = ""

[string]$Global:Version = ""

[string]$Global:WebSiteName = ""

[string]$Global:WebSitePath = ""

[string]$Global:WebSiteAppLogPath = ""

[string]$Global:ShareName = ""

[string]$Global:PRDDNS = ""

[string]$Global:VirtDirName = ""

[string]$Global:HTTP_IP = ""

[string]$Global:HTTP_Port = ""

[string]$Global:HTTP_HostHeader = ""

[string]$Global:HTTPS_IP = "" #Should match HTTP_IP

[string]$Global:HTTPS_Port = ""

[string]$Global:HTTPS_CertName = ""

[string]$Global:PostBuildScript = ""

[string]$Global:PostBuildScriptDescript = ""

 

 

[string]$Global:WhoWeAre = ""

[string]$Global:WhatWeDo = ""

[string]$Global:HowDoYouGetAccess = ""

 

#-----------------------------------------------------------[Functions]------------------------------------------------------------

 

###########################################################

### Get-CurrentLine                                     ###

###########################################################

Function Get-CurrentLine {

    $Myinvocation.ScriptlineNumber

}

 

###########################################################

### LogIt                                               ###

###########################################################

Function LogIt {

    Param(

        [string]$theMsg,

        [string]$Color = "White"

    )

    <#

This function Logs messages to the Console Log

#>

    if ($theMsg.Contains("***")) { $Color = "Cyan" }

    Write-Host "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-$($theMsg)"  -f $Color

    "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-$($theMsg)" | Out-File -Append -FilePath WSA:\$Global:ConsoleLog

}# LogIt

 

###########################################################

### Process Errors                                      ###

###########################################################

Function Process-Error {

    Param($ErrCode,

        $ErrMsg)

    <#

This function Logs $Error messages to the Console Log

#>

    $LineNum = $($Myinvocation.ScriptlineNumber)

   

    if ($ErrCode) {

   

        foreach ($Err in $ErrCode) {

            Write-Host "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-ERROR Description: $Err.Exception"  -f Red

            Write-Host "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-ERROR Position   : $($Err.InvocationInfo.PositionMessage)"  -f Red

 

            If ($Err.InvocationInfo.Line.length -eq 0) {

                Write-Host "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-ERROR Line       : $($LineNum)"  -f Red

            }

            else {

                Write-Host "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-ERROR Line       : $($Err.InvocationInfo.Line)"  -f Red

            }

            Write-Host "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-ERROR Stack      : $($Err.ScriptStackTrace)"  -f Red

            Write-Host "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-ERROR What To Do : $ErrMsg" -f Red

 

            "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-ERROR Description: $Err.Exception" | Out-File -Append -FilePath WSA:\$Global:ErrorLog

            "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-ERROR Position   : $($Err.InvocationInfo.PositionMessage)" | Out-File -Append -FilePath WSA:\$Global:ErrorLog

            If ($Err.InvocationInfo.Line.length -eq 0) {

                "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-ERROR Line       : $($LineNum)" | Out-File -Append -FilePath WSA:\$Global:ErrorLog

            }

            else {

                "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-ERROR Line       : $($Err.InvocationInfo.Line)" | Out-File -Append -FilePath WSA:\$Global:ErrorLog

            }

            "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-ERROR Stack      : $($Err.ScriptStackTrace)" | Out-File -Append -FilePath WSA:\$Global:ErrorLog

            "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-ERROR What To Do : $ErrMsg" | Out-File -Append -FilePath WSA:\$Global:ErrorLog

 

            "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-ERROR Description: $Err.Exception" | Out-File -Append -FilePath WSA:\$Global:ConsoleLog

            "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-ERROR Position   : $($Err.InvocationInfo.PositionMessage)" | Out-File -Append -FilePath WSA:\$Global:ConsoleLog

            If ($Err.InvocationInfo.Line.length -eq 0) {

                "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-ERROR Line       : $($LineNum)" | Out-File -Append -FilePath WSA:\$Global:ConsoleLog

            }

            else {

                "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-ERROR Line       : $($Err.InvocationInfo.Line)" | Out-File -Append -FilePath WSA:\$Global:ConsoleLog

            }

            "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-ERROR Stack      : $($Err.ScriptStackTrace)" | Out-File -Append -FilePath WSA:\$Global:ConsoleLog

            "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-ERROR What To Do : $ErrMsg" | Out-File -Append -FilePath WSA:\$Global:ConsoleLog

        }#Foreach Err

        return

    }

    else {

        "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-UNKNOWN: called from:$($LineNum) $($ErrMsg)" | Out-File -Append -FilePath WSA:\$Global:ErrorLog

        "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-UNKNOWN: called from:$($LineNum) $($ErrMsg)" | Out-File -Append -FilePath WSA:\$Global:ConsoleLog

        return

    }# If ErrCode

   

}# Process-Error

 

###########################################################

### Sleep                                               ###

###########################################################

Function TimeDelay {

    Param (

        [int]$TimetoSleep = 1,

        [Switch]$Quiet = $false

    )

    <#

This function sleeps for a $TimeToSleep period of time to permit background operations to complete

#>

 

    $SleepMsg = "Sleeping for $TimeToSleep Seconds to compensate for slow Servers"

    if (-not $Quiet) {

        Logit $SleepMsg

    }

    Start-Sleep -Seconds $TimeToSleep # Delay to compensate for slow Servers

}# TimeDelay

 

###########################################################

### IsUserPresent                                       ###

###########################################################

function IsUserPresent {

<#

This function Checks to see if there is a user present to interact with

#>

 

    $HostInfo = Get-Host

    if ($HostInfo.UI.RawUI.windowtitle) {

        #"$($HostInfo.UI.RawUI.WindowTitle) user enabled"| Out-File -FilePath \\CIWSDBXD13740\E$\process_Result.txt -Append

        Return $True

    }

    else {

        #"$($HostInfo.UI.RawUI.WindowTitle) No User found"| Out-File -FilePath \\CIWSDBXD13740\E$\process_Result.txt -Append

        Return $False

    }

}# IsUserPresent

 

###########################################################

### Setup-Credentials                                   ###

###########################################################

function Setup-Credentials {

<#

This will check for Passwords and determine if they have been supplied.

If not it will check if it is running with a user present to enter passwords

If not it will shut down the program

 

 

#>

 

# Not running interactive and PBPassword is blank

    if ((-Not(IsUserPresent)) -and ($Global:PBPassword -eq "")) {

        $Global:Processing = $False

        Write-Host "Running in Non-interactive mode and PBPassword is blank for $($Global:PBLogon)" -ForegroundColor red -BackgroundColor White

        Write-Host "$($Error) $($WhatToDo)" -ForegroundColor red -BackgroundColor White

        Write-Host "1002A - Running in Non-interactive mode and PBPassword is blank for $($Global:PBLogon)" -ForegroundColor red -BackgroundColor White

        "1002A - Running in Non-interactive mode and PBPassword is blank for $($Global:PBLogon)" | out-file -FilePath C:\Scripts\Error.txt

 

        Return

    }

 

# Not running interactive and VenafiPassword is blank

    if ((-Not(IsUserPresent)) -and ($Global:VenafiPassword -eq "")) {

        $Global:Processing = $False

        Write-Host "Running in Non-interactive mode and VenafiPassword is blank for $($Global:VenafiLogon)" -ForegroundColor red -BackgroundColor White

        Write-Host "$($Error) $($WhatToDo)" -ForegroundColor red -BackgroundColor White

        Write-Host "1002A - Running in Non-interactive mode and VenafiPassword is blank for $($Global:VenafiLogon)" -ForegroundColor red -BackgroundColor White

        "1002B - Running in Non-interactive mode and VenafiPassword is blank for $($Global:PBLogon)" | out-file -FilePath C:\Scripts\Error.txt

        Return

    }

 

# If Venafi password is blank then prompt

    if ([string]::IsNullOrWhiteSpace($Global:PBPassword)) {

        Write-Host "`r`n`r`nEnter your PlayBook Password for $($Global:PBLogon): " -ForegroundColor Yellow

        $SecurePBPassword = Read-Host -AsSecureString -Prompt "Enter your PlayBook Password for $($Global:PBLogon):"

# Create **PSCredential** object from the values in the Global:PBLogon and $SecurePBPassword variables.

        $Global:PBCredential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $Global:PBLogon , $SecurePBPassword

    }

    else {

# Convert Password

        $SecurePBPassword = ConvertTo-SecureString -String $Global:PBPassword -AsPlainText -Force

# Create **PSCredential** object from the values in the Global:PBLogon and $SecurePBPassword variables.

        $Global:PBCredential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $Global:PBLogon , $SecurePBPassword

    }

 

# Convert back to Text

    $cleartextPBPassword = $Global:PBCredential.GetNetworkCredential().Password

 

# If still blank abort

    if ([string]::IsNullOrWhiteSpace($cleartextPBPassword)) {

        Write-Host "1002A - PBPassword is blank for $($Global:PBLogon)" -ForegroundColor red -BackgroundColor White

        $Global:Processing = $false

        return

    }

 

    $cleartextPBPassword =  ""

 

# If PBLogon ID is same as Venafi copy password

    if (($Global:VenafiLogon -ieq $Global:PBLogon) -and ([string]::IsNullOrWhiteSpace($Global:VenafiPassword))) {

        $SecureVenafiPassword = $SecurePBPassword

# Create **PSCredential** object from the values in the Global:PBLogon and $SecurePBPassword variables.

        $Global:VenafiCredential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $Global:VenafiLogon , $SecureVenafiPassword

# Convert back to Text

        $Global:VenafiPassword = $Global:VenafiCredential.GetNetworkCredential().Password

    }

 

# If Venafi password is blank then prompt

    if ([string]::IsNullOrWhiteSpace($Global:VenafiPassword)) {

        Write-Host "`r`n`r`nEnter your Venafi Password for $($Global:VenafiLogon): " -ForegroundColor Yellow

        $SecureVenafiPassword = Read-Host -AsSecureString -Prompt "Enter your Venafi Password for $($Global:VenafiLogon): "

# Create **PSCredential** object from the values in the Global:PBLogon and $SecurePBPassword variables.

        $Global:VenafiCredential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $Global:VenafiLogon , $SecureVenafiPassword

    }

    else {

# Convert Password

        $SecureVenafiPassword = ConvertTo-SecureString -String $Global:VenafiPassword -AsPlainText -Force

# Create **PSCredential** object from the values in the Global:PBLogon and $SecurePBPassword variables.

        $Global:VenafiCredential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $Global:VenafiLogon , $SecureVenafiPassword

    }

 

# Convert back to Text

    $cleartextVenafiPassword = $Global:VenafiCredential.GetNetworkCredential().Password

 

# If still blank abort

    if ([string]::IsNullOrWhiteSpace($cleartextVenafiPassword)) {

        Write-Host "1002B - VenafiPassword is blank for $($Global:VenafiLogon)" -ForegroundColor red -BackgroundColor White

        $Global:Processing = $false

        return

    }

    $cleartextVenafiPassword = ""

 

}# Setup-Credentials

 

###########################################################

### Get-WindowsVersion                                  ###

###########################################################

function Get-WindowsVersion {

    Param([psobject]$theObject)

 

    $Myinvocation.ScriptlineNumber

    $ErrorActionPreference = "Continue"

    Logit "*** Get_WindowsVersion, Line:$(Get-CurrentLine) called from:$($Myinvocation.ScriptlineNumber)"

    $ServerName = $theObject.ServerName

    Try {

        $Temp = (Get-WmiObject Win32_OperatingSystem -ComputerName $ServerName -Authentication Default).Name.split("|")

        $Temp2 = $Temp[0]

    }  

    Catch {

        LogIt "Error attempting to connect to $($ServerName) from $($env:USERDOMAIN) Domain - $Error"

        $OSVersion = "unknown"

        $Global:Processing = $false

        return

    }

    Finally {

        $OSVersion = $Temp2.ToLower()

        LogIt "$($ServerName) is running '$($OSVersion)'"

 

    }

 

    $IISVersion = switch -wildcard ($OSVersion) {

        "*2003*" { 'IIS 6.0 Web Server (32bit)' }

        "*2008 E*" { '7.0' }

        "*2008 S*" { '7.0' }

        "*2008 R2*" { '7.5' }

        "*2012 E*" { '8.0' }

        "*2012 S*" { '8.0' }

        "*2012 R2*" { '8.5' }

        "*2016 E*" { '10.0' }

        "*2016 S*" { '10.0' }

        "*2016 R2*" { '10.5' }

        "*2019 E*" { '10.0' }

        "*2019 S*" { '10.0' }

    }# Switch

 

    $WindowsYear = switch -wildcard ($OSVersion) {

        "*2003*" { '2003' }

        "*2008 E*" { '2008' }

        "*2008 S*" { '2008' }

        "*2008 R2*" { '2008' }

        "*2012 E*" { '2012' }

        "*2012 S*" { '2012' }

        "*2012 R2*" { '2012' }

        "*2016 E*" { '2016' }

        "*2016 S*" { '2016' }

        "*2016 R2*" { '2016' }

        "*2019 E*" { '2019' }

        "*2019 S*" { '2019' }

    }# Switch

 

    Logit "Server: $ServerName is running: $OSVersion which means it is IIS Version: $IISVersion"

    $theObject.WindowsVersion = $OSVersion

    $theObject.IISVersion = $IISVersion

    $theObject.WindowsYear = $WindowsYear

}# Get-WindowsVersion

 

 

###########################################################

### Validate-PlayBook                                   ###

###########################################################

Function Validate-PlayBook {

    Param(

        [xml]$PlayBook  )

    Logit "*** Validate-PlayBook, Line:$(Get-CurrentLine) called from:$($Myinvocation.ScriptlineNumber)"

    <#

                This function backs up the existing WebSites and Metabase

before restoring the MetaBase back to how it looked when IIS was first installed.

#>

    $ErrorActionPreference = "SilentlyContinue"

    $error.clear()

    # Display Bindings in Log 

    $PlayBook.PB.WebSite.Bindings | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

 

    foreach ($Server in $PlayBook.PB.WebSite.Bindings.Server) {

 

        If (($Global:CurrentEnv -ieq $Server.Environment) -and ($Global:PhysicalServerName -ieq $Server.Name)) {

            [string]$Global:HTTP_IP = $($Server.IPAddress)

            [string]$Global:HTTP_Port = $($Server.HttpPort)

            [string]$Global:HTTP_HostHeader = $($Server.HostName)

            [string]$Global:HTTPS_HostHeader = $($Server.HostName)

            [string]$Global:HTTP_HostHeader = $Global:HTTP_HostHeader.ToLower()

            [string]$Global:HTTPS_HostHeader = $Global:HTTPS_HostHeader.ToLower()

            [string]$Global:HTTPS_IP = $($Server.IPAddress) #Should match HTTP_IP

            [string]$Global:HTTPS_Port = $($Server.HttpsPort)

            [string]$Global:HTTPS_CertName = $($Server.HostName)

            [string]$Global:HTTPS_CertName = $Global:HTTPS_CertName.ToLower()

            "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-Server.Name`t`t`t$($Server.Name)" | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

            "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-Server.Environment:`t`t$($Server.Environment)" | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

            "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-Server.IPAddress:`t`t$($Server.IPAddress)" | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

            "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-Server.HttpPort:`t`t$($Server.HttpPort)" | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

            "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-Server.HttpsPort:`t`t$($Server.HttpsPort)" | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

            "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-Server.HostName:`t`t$($Server.HostName)" | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

            "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-Server.Description:`t`t$($Server.Description)" | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

 

        } # CurrentEnv

 

    } # Foreach Server

 

    if ($Global:Http_HostHeader -ieq "") {

        $Global:Processing = $False

        Process-Error "1003" "Environment $Global:CurrentEnv and Server $Global:PhysicalServerName Not Found in Bindings"

        Logit "Environment $Global:CurrentEnv and Server $Global:PhysicalServerName Not Found in Bindings"

    }

 

}# Validate-PlayBook

 

###########################################################

### Extract Basic Info from PlayBook                    ###

###########################################################

Function Extract-BasicInfo {

    Param(

        [XML]$PlayBook

    )

    Logit "*** Extract-BasicInfo, Line:$(Get-CurrentLine) called from:$($Myinvocation.ScriptlineNumber)"

    <#

Plull basic information from the playbook

#>

 

    # Default Hive to Web Hosting Windows

    $Global:VenafiHive = $PlayBook.PB.WebSite.VenafiHive

    If (-not($Global:VenafiHive)) {

        $Global:VenafiHive = "Web Hosting Windows"

    }

 

    # Test for PlayBook Version to determine where to look for values

    if ($PlayBook.PB.Version -lt 2) {

        $Global:ASGName = $PlayBook.PB.WebSite.ASG.Name

        $Global:HPSMAssignmentGroup = $PlayBook.PB.WebSite.ASG.HPSMAssignmentGroup

        $Global:ApplicationId = $PlayBook.PB.WebSite.ApplicationNum

        $Global:TFSGroup = $PlayBook.PB.WebSite.ASG.TFSGroup

    }

    else {

        $Global:ASGName = $PlayBook.PB.WebSite.ASGName

        $Global:HPSMAssignmentGroup = $PlayBook.PB.WebSite.HPSMAssignmentGroup

        $Global:ApplicationId = $PlayBook.PB.WebSite.ApplicationNum

        $Global:TFSGroup = $PlayBook.PB.WebSite.TFSGroup

    }

 

    $ErrorActionPreference = "Continue"

    $error.clear()

    $Global:AppPool = $($PlayBook.PB.WebSite.AppPool.Name)

    $Global:PRDDNS = $($PlayBook.PB.WebSite.PRDDNS).ToLower()

    $Global:LOB = $PlayBook.PB.WebSite.LOB

    $Global:WebSiteName = $PlayBook.PB.WebSite.Name

    $Global:Release = $PlayBook.PB.WebSite.Release

    $Global:Version = $PlayBook.PB.WebSite.Version

    $Global:ShareName = "$($Global:LOB)_$($Global:WebSiteName)"

    $Global:PS1File = ".\$($Global:LOB)_$($Global:WebSiteName)_PS1File_$($Global:TimeStamp).ps1"

    $Global:WhoWeAre = $PlayBook.PB.WebSite.StartPage.WhoWeAre

    $Global:WhatWeDo = $PlayBook.PB.WebSite.StartPage.WhatWeDo

    $Global:HowDoYouGetAccess = $PlayBook.PB.WebSite.StartPage.HowDoYouGetAccess

    $Global:PostBuildScript = $PlayBook.PB.WebSite.PostBuildScript.Name

    $Global:PostBuildScriptDescript = $PlayBook.PB.WebSite.PostBuildScript.Description

}# Extract-BasicInfo

 

###########################################################

### Validate that this is a Single WebSite              ###

###########################################################

Function Validate-SingleSite {

    Param (

        [string]$SiteName

    )

 

    Logit "*** Validate-SingleSite, Line:$(Get-CurrentLine) called from:$($Myinvocation.ScriptlineNumber)"

    <#

                This function checks to make sure there is not already a web site on the serverwith a different name.

Or that there is not something installed on the Default Web Site

#>

    $ErrorActionPreference = "SilentlyContinue"

    $error.clear()

 

    $DefaultSite = $False

    $OlderVersion = $False

    $TooManySitesExist = $False

    #   $Sites.Count

    #See if anything is installed on Default Web Site

    $VendorOnDefault = Get-ChildItem 'IIS:\Sites\Default Web Site\'

    if (-not ($VendorOnDefault.Count = 3)) {

        $TooManySitesExist = $True

    }

 

    $Sites = Get-ChildItem IIS:\Sites

    #    $VendorOnDefault.Count

 

    foreach ($site in $Sites) {

        #        $Site.Name

        if ($Site.Name -ieq 'Default Web Site') {

            $DefaultSite = $True

            Continue

        }

        if ($Site.Name -ieq $SiteName) {

            $OlderVersion = $True

            Continue

        }

        else {

            $TooManySitesExist = $True

        }

    }

    if ($TooManySitesExist) {

        $Global:Processing = $False

        Process-Error "1007" "Environment $Global:CurrentEnv and Server $Global:PhysicalServerName More than one website cannot be added to this server"

        Logit "Environment $Global:CurrentEnv and Server $Global:PhysicalServerName More than one website cannot be added to this server"

    }

    return $TooManySitesExist

}# Validate-SingleSite

 

###########################################################

### Look-InVenafi                                       ###

###########################################################

Function Look-InVenafi {

    Param(

        [string]$PlayBookPath  )

    Logit "*** Look-InVenafi, Line:$(Get-CurrentLine) called from:$($Myinvocation.ScriptlineNumber)"

    <#

                This function backs up the existing WebSites and Metabase

before restoring the MetaBase back to how it looked when IIS was first installed.

#>

    $ErrorActionPreference = "SilentlyContinue"

    $VerbosePreference = "SilentlyContinue"

    $error.clear()

 

    # Call NewSite2_GetCert to download the cert from Venafi if it exists           

    $CertObj = New-Object -TypeName psobject

    $CertObj | Add-Member -MemberType NoteProperty -Name CertName                -Value $Global:HTTPS_CertName

    $CertObj | Add-Member -MemberType NoteProperty -Name Env                     -Value $Global:CurrentEnv

    $CertObj | Add-Member -MemberType NoteProperty -Name HPSMApplId              -Value $Global:ApplicationId

    $CertObj | Add-Member -MemberType NoteProperty -Name HPSMAssignGroup         -Value $Global:HPSMAssignmentGroup

    $CertObj | Add-Member -MemberType NoteProperty -Name ASGName                 -Value $Global:ASGName

    $CertObj | Add-Member -MemberType NoteProperty -Name VenafiHive              -Value $Global:VenafiHive

    $CertObj | Add-Member -MemberType NoteProperty -Name VenafiCredentials       -Value $Global:VenafiCredential

    $CertObj | Add-Member -MemberType NoteProperty -Name CertLog                 -Value "prefetch"

    $CertObj | Add-Member -MemberType NoteProperty -Name Successful              -Value $false

 

    if ($Venafi) {           

        #. {C:\TFS\Enterprise-WebHosting\PowerShellScripts\WebSiteAutomation\Trunk\WebSiteAutomation\WebSiteAutomation\WebSiteAutomation\NewSite2_GetCert.ps1 $CertObj}

        . { C:\Scripts\IIS\NewSite2_GetCert.ps1 $CertObj }

    }# $Venafi

    $CertObj.CertLog | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

    if ($CertObj.Successful) {

        Write-Host "A Certificate was found and downloaded from Venafi for $($CertObj.CertName)" -ForegroundColor Yellow

        Logit "A Certificate was found and downloaded from Venafi for $($CertObj.CertName)"

 

    }

    else {

        Write-Host "No Certificate found for $($CertObj.CertName) in Venafi" -ForegroundColor yellow

        Logit "No Certificate found for $($CertObj.CertName) in Venafi"

    }

    $CertObj = "" # destroy the Object

 

    # not needed on production Domain

    if ($Global:Domain -ieq "INTERNAL" ) {

        return

    }

 

    #   remove-item -Path "$($Global:HostingDrive)\INTERNAL_CAs\" -Recurse -force | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

}# Look-InVenafi

 

###########################################################

### BackUp the Metabase                                 ###

###########################################################

Function CheckIfBackupRequested {

   Param(

        [boolean]$Backup,

        [string]$PlayBookPath  )

    Logit "*** CheckIfBackupRequested, Line:$(Get-CurrentLine) called from:$($Myinvocation.ScriptlineNumber)"

    <#

                This function backs up the existing WebSites and Metabase

before restoring the MetaBase back to how it looked when IIS was first installed.

#>

    $ErrorActionPreference = "SilentlyContinue"

    $error.clear()

    if ($Backup) {

 

        # Call NewSite2_Backup to Backup the Metabase and Files           

        $BackUpObj = New-Object -TypeName psobject

        $BackUpObj | Add-Member -MemberType NoteProperty -Name LOB               -Value $Global:LOB

        $BackUpObj | Add-Member -MemberType NoteProperty -Name WebSiteName       -Value $Global:WebSiteName

        $BackUpObj | Add-Member -MemberType NoteProperty -Name Release           -Value $Global:Release

        $BackUpObj | Add-Member -MemberType NoteProperty -Name TimeStamp         -Value $Global:TimeStamp

        $BackUpObj | Add-Member -MemberType NoteProperty -Name PlayBookPath      -Value $PlayBookPath

        $BackUpObj | Add-Member -MemberType NoteProperty -Name BackUpLog         -Value "prefetch"

        $BackUpObj | Add-Member -MemberType NoteProperty -Name MetaBaseSuccess   -Value $false

        $BackUpObj | Add-Member -MemberType NoteProperty -Name FileBackUpSuccess -Value $false

                   

        #      . {C:\TFS\Enterprise-WebHosting\PowerShellScripts\WebSiteAutomation\Trunk\WebSiteAutomation\WebSiteAutomation\WebSiteAutomation\NewSite2_Backup.ps1 $BackUpObj}

        . { C:\Scripts\IIS\NewSite2_Backup.ps1 $BackUpObj }

 

        # Write output of Backup to logs

        $BackUpObj.BackUpLog | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

        if ($BackUpObj.MetabaseSuccess) {

            Logit "A backup of the Metabase for $($BackUpObj.LOB)_$($BackUpObj.WebSiteName) was successful"

        }

        else {

            Logit "A backup of the Metabase for $($BackUpObj.LOB)_$($BackUpObj.WebSiteName) FAILED"

            $Global:Processing = $False

            Process-Error "1001A" "A backup of the Metabase for $($BackUpObj.LOB)_$($BackUpObj.WebSiteName) FAILED"

        }

 

        if ($BackUpObj.FileBackupSuccess) {

            Logit "A backup of the Files for $($BackUpObj.LOB)_$($BackUpObj.WebSiteName) was successful"

        }

        else {

            Logit "A backup of the Files for $($BackUpObj.LOB)_$($BackUpObj.WebSiteName) FAILED"

            $Global:Processing = $False

            Process-Error "1001B" "A backup of the Files for $($BackUpObj.LOB)_$($BackUpObj.WebSiteName) FAILED"

        }

       

        $BackUpObj = "" # destroy the Object

    }# Backup

 

}# CheckIfBackupRequested

 

###########################################################

### Reset the Metabase                                  ###

###########################################################

Function Reset-WebSite {

    Param()

    Logit "*** Reset-WebSite, Line:$(Get-CurrentLine) called from:$($Myinvocation.ScriptlineNumber)"

    <#

This function sets IIS back to a known state.

After IIS was installed and all of the defaults have been applied and removes all files.

#>

    $ErrorActionPreference = "SilentlyContinue"

    $error.clear()

 

    # Stop IIS to free up Logs

    iisreset /Stop | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

    $ErrorActionPreference = "SilentlyContinue"

    $error.clear()

 

    # New stuff Starts here

    $ErrorActionPreference = "SilentlyContinue"

    $error.clear()

    Try {

        $Global:WebSiteName = $PlayBook.PB.WebSite.Name

        Logit  "Deleting WebSite $($Global:WebSiteName)"

        Get-WebSite -name "$($Global:WebSiteName)" -Verbose | Remove-WebSite  -Verbose

    }

    Catch {

        "$($Global:WebSiteName) Does not exist, continuing"

    }

    Finally {

        "$($Global:WebSiteName) Deleted"

    }

 

    Logit  "Deleting AppPools"

 

    $ErrorActionPreference = "SilentlyContinue"

    $error.clear()

    foreach ($AppPool in $PlayBook.PB.WebSite.AppPool.Name) {

        Try {

            Remove-WebAppPool -name $AppPool -Verbose

        }

        Catch {

            "$($AppPool) Does not exist"

        }

        Finally {

            "$($AppPool) Deleted"

        }

    }# foreach AppPool

 

    # New stuff ends here

 

    Logit  "Deleting Shares"

    #    Net Share $Global:ShareName /Delete | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

    Remove-SmbShare -name $Global:ShareName -Force | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

 

    Logit  "Deleting Directories"

    Remove-Item -Path "E:\LoadBalance\$($Global:LOB)\$($Global:WebSiteName)\"    -Recurse -Force

    Remove-Item -Path "E:\pages\$($Global:LOB)\$($Global:WebSiteName)\"          -Recurse -Force

    Remove-Item -Path "F:\Logs\TraceLogs\$($Global:LOB)\$($Global:WebSiteName)\" -Recurse -Force

    Remove-Item -Path "F:\Logs\WebLogs\$($Global:LOB)\$($Global:WebSiteName)\"   -Recurse -Force

    Remove-Item -Path "F:\Logs\WMSVC\$($Global:LOB)\$($Global:WebSiteName)\"     -Recurse -Force

    #Remove-SmbShare -Name $Global:ShareName -Force | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

 

   

    #Restart IIS

    IISRESET /Start | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

 

    TimeDelay 1 # Delay to compensate for slow Symphony Servers

}# Reset-WebSite

 

###########################################################

### Process Feature Delegation                          ###

###########################################################

Function Process-FeatureDelegation {

    Param(

        [XML]$PlayBook

    )

    Logit "*** Process-FeatureDelegation, Line:$(Get-CurrentLine) called from:$($Myinvocation.ScriptlineNumber)"

    <#

                Set the Features before building web site

                NOTE: This has to be done immediately after restore befor any IIS changes are done

#>

    $ErrorActionPreference = "SilentlyContinue"

    $error.clear()

 

    foreach ($Feature in $PlayBook.PB.WebSite.FeatureDelegation) {

        [string]$FeatureName = $($Feature.Name)

        [string]$FeatureState = $($Feature.State)

        [string]$ActualFeature =       ""

        "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-Feature.Name:`t$($Feature.Name)" | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

        "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-Feature.State:`t$($Feature.State)" | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

 

        $ActualFeature = switch ($FeatureName) {

            "DirectoryBrowsing" { "directoryBrowse" }

            "AuthorizationRules"         { "authorization" }

            "FeatureDelegation" { "FeatureDelegation" }

            Default { "Invalid" }

        } #Switch

 

        If ($ActualFeature -ieq "Invalid") {

            $Global:Processing = $false

            "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-This is an invalid Feature" | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

            "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-This is an invalid Feature" | Out-File -Append -FilePath  WSA:\$Global:ErrorLog

        } # Validate FeatureName

 

        If (($FeatureState -ine "lock") -and ($FeatureState -ine "unlocked")) {

            $Global:Processing = $false

            "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-This is an invalid State" | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

            "$(Get-Date -format yyyyMMdd-HH.mm.ss.fff)-$($ScriptName)-This is an invalid State" | Out-File -Append -FilePath  WSA:\$Global:ErrorLog

        } # Validate FeatureState

 

        & C:\Windows\System32\InetSrv\Appcmd.exe $FeatureState config /section:$ActualFeature  /commit:APPHOST

        if (!$?) {

            $Global:Processing = $false

            Process-Error $Error "An error has Setting Feature $($ActualFeature) to $($FeatureState) for $($Global:CurrentEnv) Environment"

  