[cmdletbinding()]

#requires -version 4

Param(

    [Parameter(Mandatory = $true, HelpMessage = "Reqiured and in format of psobject")]

    [psobject]$BackUpObj

)

 

###########################################################

$ScriptName = "NewSite2_Backup"

$ScriptVersion = "2019.02.22"

$ScriptAuthor = "Marshall Buck"

$ScriptRevised = "02/22/2019"

$ScriptCreated = "02/28/2017"

"`r`nParameters Supplied to $($ScriptName) this time:"

"LOB=$($BackUpObj.LOB)"

"WebSiteName=$($BackUpObj.WebSiteName)"

"Release=$($BackUpObj.Release)"

"TimeStamp=$($BackUpObj.TimeStamp)"

"`r`n"

$Error.Clear()

<#

.SYNOPSIS

  This examines the Application PlayBook Name and backs up the confiuration and Files of existing web site.

.DESCRIPTION

  <Brief description of script>

.PARAMETER <Parameter_Name>

    <Brief description of parameter input required. Repeat this attribute if required>

.INPUTS

  <Inputs if any, otherwise state None>

.OUTPUTS

  <Outputs if any, otherwise state None - example: Log file stored in C:\Windows\Temp\<name>.log>

.NOTES

  Version:        0.2.13

  Author:         Marshall Buck

  Creation Date:  <Date>

  Purpose/Change: Initial script development

 

.EXAMPLE

  <Example goes here. Repeat this attribute for more than one example>

#>

 

#---------------------------[DECLARATIONS]--------------------------------

 

#---------------------------[FUNCTIONS]--------------------------------

###########################################################

### Backup-Configurations                               ###

###########################################################

function Backup-Configurations {

    Param

    (

        [psobject]$BackUpObj

    )

 

    $Msg = "Backup Before running LOB=$($BackUpObj.LOB)  Web Site=$($BackUpObj.WebSiteName) Release=$($BackUpObj.Release) on $($BackUpObj.TimeStamp)"

    C:\Windows\System32\inetsrv\appcmd.exe Add Backup $Msg | Out-File -Append -FilePath C:\Scripts\temp.txt

    C:\Windows\System32\inetsrv\appcmd.exe List Backup     | Out-File -Append -FilePath C:\Scripts\temp.txt # Display all existing backups

    $BackUpObj.MetabaseSuccess = $True

}# Backup-Configuration

 

###########################################################

### ZipUp-Files                                         ###

###########################################################

function ZipUp-Files {

    param

    (

        [psobject]$BackUpObj

    )

    $ErrorActionPreference = "SilentlyContinue"

    $ErrorActionPreference = "Continue"

    $error.clear()

 

    $Source = "E:\Pages\$($BackUpObj.LOB)\$($BackUpObj.WebSiteName)\"

    $DestPath = "F:\PageBack\$($BackUpObj.LOB)\$($BackUpObj.WebSiteName)"

    $Destination = "$($DestPath)\Backup_$($TimeStamp).Zip"

 

    $error.clear()

    if (-Not (test-path -path $($DestPath))) {

        new-item -Path $($DestPath) -ItemType Directory | Out-Null

    }

    "Source=$($Source)" | Out-File -Append -FilePath C:\Scripts\temp.txt

    "Destination=$($Destination)" | Out-File -Append -FilePath C:\Scripts\temp.txt

    if (test-path -path $($Source)) {

        $error.clear()

        Try {

            Add-Type -AssemblyName "system.io.compression.filesystem"

            [io.compression.zipfile]::CreateFromDirectory($Source, $Destination)  | Out-File -Append -FilePath C:\Scripts\temp.txt

        }

        Catch {

            "Backup of Files - FAILED" | Out-File -Append -FilePath C:\Scripts\temp.txt

            $BackUpObj.MetabaseSuccess = $False

        }

        Finally {

            "Backup of Files - Successful" | Out-File -Append -FilePath C:\Scripts\temp.txt

            $BackUpObj.FileBackupSuccess = $True

        }# Try Zip

    }

    else {

        "Backup of Files - $($Source) doesn't exist so nothing to backup" | Out-File -Append -FilePath C:\Scripts\temp.txt

        $BackUpObj.FileBackupSuccess = $True

    }# Does Source exist

}# Zipup-Files

 

#---------------------------[EXECUTION STARTS HERE]--------------------------------

"$ScriptName $ScriptVersion - Starting"  | Out-File -FilePath C:\Scripts\temp.txt

Backup-Configurations $BackUpObj

ZipUp-Files $BackUpObj

"$ScriptName $ScriptVersion - Ending"  | Out-File -Append -FilePath C:\Scripts\temp.txt

   

$BackupObj.BackUpLog = get-content -Path C:\Scripts\temp.txt

Return

 

 