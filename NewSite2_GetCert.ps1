[cmdletbinding()]

#requires -version 4

Param(

    [Parameter(Mandatory = $true, HelpMessage = "Required, The Certificate Object")]

    [PSObject]$CertObj

)

###########################################################

$ScriptName = "NewSite2_GetCert"

$ScriptVersion = "2019.03.13"

$ScriptAuthor = "Marshall Buck"

$ScriptRevised = "03/13/2019"

$ScriptCreated = "01/31/2019"

 

<#

.SYNOPSIS

  This Calls Venify API to get Certs to be installed in the Certificate Store.

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

$Global:Domain = $env:USERDOMAIN

$Global:IsThereARootCA = $False

$Global:HostingDrive = "F:"

 

###########################################################

### Copy-Copy-CAs                                       ###

###########################################################

Function Copy-CAs {

 

    Logit "*** Copy-CAs, Line:$(Get-CurrentLine) called from:$($Myinvocation.ScriptlineNumber)"

    <#

If it INTERNAL Server skip this step

otherwise copy the INTERNAL CA to this test server

#>

    $ErrorActionPreference = "Continue"

    $error.clear()

 

    # not needed on production Domain

    if ($Global:Domain -ieq "INTERNAL" ) {

        return

    }

 

    # Create the LoadBalance Directory, Copy files and set the permissions

    New-Item -Path "$($Global:HostingDrive)\INTERNAL_CAs\" -type directory -Force -ErrorAction SilentlyContinue | Out-File -Append -FilePath "C:\Scripts\Temp.txt"

    if (!$?) {

        Process-Error $Error "An error has occurred Creating INTERNAL_CAs Directory"

    }

    else {

        Logit "INTERNAL_CAs Directory Created"

    }

   

    # Copy the INTERNAL CAs from automation files to the F: drive of local machine

    $FileNameIn = "WSA:\Files\INTERNAL_CAs\*.cer"

    $FileNameOut = "$($Global:HostingDrive)\INTERNAL_CAs\"

               

    Copy-item "$FileNameIn"  "$FileNameOut" -Recurse -Force -Verbose | Out-File -Append -FilePath  "C:\Scripts\Temp.txt"

    if (!$?) {

        Process-Error $Error "An error has occurred Copying INTERNAL_CAs Files to server"

    }

    else {

        Logit "INTERNAL_CAs Files copied to Server"

    }

                               

}# Copy-CAs

 

###########################################################

### Check-ForRootCA                                     ###

###########################################################

function Check-ForRootCA {

 

    Logit "*** Check-ForRootCA, Line:$(Get-CurrentLine) called from:$($Myinvocation.ScriptlineNumber)"

    <#

This checks to see if a cert exists and sets the $Global:IsThereARootCA to true if it does

#>

    $ErrorActionPreference = "Continue"

    $error.clear()

 

    # not needed on production Domain

    if ($Global:Domain -ieq "INTERNAL" ) {

        return

    }

 

    $Root = Get-ChildItem Cert:\LocalMachine\Root

    foreach ($CA in $Root) {

        $CommaPos = $CA.Subject.indexof(",")

        if ($CommaPos -gt 0) {

            $Subject = $($CA.Subject.substring(0, $CommaPos))

        }

        else {

            $Subject = $($CA.Subject)

        }

        $RootCAName = "CN=" + $("Cigna Root CA")

 

        if (($Subject) -ceq $($($RootCAName))) {

            $Global:IsThereARootCA = $True

            Logit "The Server already had INTERNAL CA so they will not be removed"

        }# If

 

    }# foreach $CA

}# Check-ForRootCA

 

###########################################################

### Install-RootCAs                                       ###

###########################################################

function Install-RootCA {

    Logit "*** Install-RootCA, Line:$(Get-CurrentLine) called from:$($Myinvocation.ScriptlineNumber)"

    <#

This installs the Cigna Root CA and the Cigna Issuing CA to the Trusted Root Certification Authorities (Root)

#>

    $ErrorActionPreference = "Continue"

    $error.clear()

 

    # not needed on production Domain

    if ($Global:Domain -ieq "INTERNAL" ) {

        return

    }

 

    # If Root CA was here already don't import again

    if ($Global:IsThereARootCA) {

        return

    }

    Import-Certificate -FilePath "$($Global:HostingDrive)\INTERNAL_CAs\Cigna_Root_CA.cer" -CertStoreLocation "Cert:\LocalMachine\Root" | Out-File -Append -FilePath  "C:\Scripts\Temp.txt"

    Import-Certificate -FilePath "$($Global:HostingDrive)\INTERNAL_CAs\Cigna_Issuing_CA.cer" -CertStoreLocation "Cert:\LocalMachine\Root" | Out-File -Append -FilePath  "C:\Scripts\Temp.txt"

 

}# Install-RootCA

 

###########################################################

### Remove-theCAs                                       ###

###########################################################

function Remove-theCAs {

    Logit "*** Remove-theCAs, Line:$(Get-CurrentLine) called from:$($Myinvocation.ScriptlineNumber)"

    <#

This will remove the Cigna Root CA and the Cigna Issuing CA from the Trusted Root Certification Authorities (Root)

#>

    $ErrorActionPreference = "Continue"

    $error.clear()

 

    # not needed on production Domain

    if ($Global:Domain -ieq "INTERNAL" ) {

        return

    }

 

    # If Root CA was here already don't delete

    if ($Global:IsThereARootCA) {

        return

    }

    #Get list of CAs

    $Root = Get-ChildItem Cert:\LocalMachine\Root

   # Loop through list

    foreach ($CA in $Root) {

        $Subject = $($CA.Subject).ToLower()

        $RootCAName = $("CN=" + "CIGNA Root CA," + "*").ToLower()

        $IssuingCAName = $("CN=" + "CIGNA Issuing CA," + "*").ToLower()

 

        if ($Subject -like $($($RootCAName))) {

            $ThumbPrint = $CA.Thumbprint

            remove-item "Cert:\LocalMachine\Root\$($ThumbPrint)"

            Logit "The INTERNAL Cigna Root CA was removed, ThumbPrint: $($ThumbPrint)"

 

        }# If Root

 

        if ($Subject -like $($($IssuingCAName))) {

            $ThumbPrint = $CA.Thumbprint

            remove-item "Cert:\LocalMachine\Root\$($ThumbPrint)"

            Logit "The INTERNAL Cigna Issuing CA was removed, ThumbPrint: $($ThumbPrint)"

        }# If Issuing

 

    }# foreach $CA

}# Remove-theCAs

 

###########################################################

### New-PKICertPassphrase                               ###

###########################################################

Function New-PKICertPassphrase {

    <#

.SYNOPSIS

Creates a new passphrase for Cigna certificate management.

 .DESCRIPTION

Returns a randomly-generated passphrase.  Default is a length of 10 characters.

 

String length can be changed with a parameter.  An alias (cert-pass) is provided.

 

.EXAMPLE

PS:>  New-PKICertPassphrase

 

.EXAMPLE

PS:> pki-pass

 

.EXAMPLE

PS:> pki-pass 16

 

.PARAMETER [int] length

The length of the passphrase (default 10)

 

.INPUTS

System.ValueType.Int

 

.OUTPUTS

System.Object.String

 

#>

    [CmdletBinding()]

    [OutputType([String])]

    Param( [int]$length = 12 )

    BEGIN {

        # Only allow [a-zA-Z0-9] in the character set

        $CharSet = $Null

        For ($i = 48; $i -le 57; $i++) { $CharSet += , [char][byte]$i } # [0-9]

        For ($i = 65; $i -le 90; $i++) { $CharSet += , [char][byte]$i } # [A-Z]

        For ($i = 97; $i -le 122; $i++) { $CharSet += , [char][byte]$i } # [a-z]

 

        $Results = ""

    }

    PROCESS {

        For ($i = 1; $i -le $length; $i++) { $Results += ($CharSet | Get-Random) }

    }

    END {

        Write-Output $Results

    } 

}# New-PKICertPassphrase

 

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

"`r`nParameters Supplied to $($ScriptName) this time:"

"CertName:          $($CertObj.CertName)"

"Env:               $($CertObj.Env)"

"VenafiHive:        $($CertObj.VenafiHive)"

"HPSM Appl Id:      $($CertObj.HPSMApplId)"

"HPSM Assign Group: $($CertObj.HPSMAssignGroup)"

"ASG Name:          $($CertObj.ASGName)"

"`r`n"

 

"CertName:          $($CertObj.CertName)"        | Out-File         -FilePath C:\Scripts\temp.txt

"Env:               $($CertObj.Env)"             | Out-File -Append -FilePath C:\Scripts\temp.txt

"VenafiHive:        $($CertObj.VenafiHive)"      | Out-File -Append -FilePath C:\Scripts\temp.txt

"HPSM Appl Id:      $($CertObj.HPSMApplId)"      | Out-File -Append -FilePath C:\Scripts\temp.txt

"HPSM Assign Group: $($CertObj.HPSMAssignGroup)" | Out-File -Append -FilePath C:\Scripts\temp.txt

"ASG Name:          $($CertObj.ASGName)"         | Out-File -Append -FilePath C:\Scripts\temp.txt

 

Copy-CAs

Check-ForRootCA

Install-RootCA

#Retrieve the certs

 

# Pull into memory the functions called in these scripts.

. "C:\Scripts\PKI\Initialize-PKIAutomation.ps1"

. "C:\Scripts\PKI\Invoke-VenafiCerticatesRetrieve.ps1"

. "C:\Scripts\PKI\Save-CertFile.ps1"

 

#Initialize the automation scripts and intialize your sessions variables. This is a function not a script.

Init-PKIAutomation

# You must be able to retrieve an API key to continue. A missing INTERNAL CA can cause this to break.

# Confirm-VenafiAPIKey with Get and Set calls.

Get-VenafiAPIKey

Set-VenafiHeader

 

#You must set the headers for the RESTfull call.

$VenafiHeaders = $script:Session.VenafiHeaders

#This is first initialized in Initialize-PKIAutomation.ps1 (persistence).

$VenafiBaseURL = $script:Session.VenafiBaseURL

###Fully Qualified Path to the certificate you want to retrieve  - This is a variable that must be updated per retrieval.

if ($($CertObj.Env) -ieq "REL" -or $($CertObj.Env) -ieq "PRD" -or $($CertObj.Env) -ieq "PFX" -or $($CertObj.Env) -ieq "TPA" -or $($CertObj.Env) -ieq "TRN") {

    $CertificateDN = "\VED\Policy\Production\Entrust Internal\$($CertObj.VenafiHive)\$($CertObj.CertName)"

}

else {

    $CertificateDN = "\VED\Policy\Test\Entrust Internal Test\$($CertObj.VenafiHive)\$($CertObj.CertName)"

}

   

#[ValidateSet("Base64","DER","PKCS #7", "Base64 (PKCS #8)", "PKCS #12", "JKS")] ## The format must be one of those following values.

$Format = "PKCS #12"

$FriendlyName = "$($CertObj.CertName)" # This should be the same as the CertificateDN declaration.

$Password = New-PKICertPassphrase #Really insert your password here please! Not AD only for the private key file. This is for the pfx file. That password is for the pfx file only to protect the private key.

$IncludeChain = $false #Do you want the trust chain with this cert? It is expected that they know enough to do the right thing.

$IncludePrivateKey = $True #Must be set to true to 12 and 8 and JKS but doesn't make sense for DER and base64 and 7 format.

 

$CertResponse = Invoke-VenafiCerticatesRetrieve `

    -VenafiHeaders $VenafiHeaders `

    -VenafiBaseURL $VenafiBaseURL `

    -CertificateDN $CertificateDN `

    -Format $Format `

    -FriendlyName $FriendlyName `

    -Password $Password `

    -IncludeChain $IncludeChain `

    -IncludePrivateKey $IncludePrivateKey

   

Write-Host "`nThe certificate format is: $Format`n"

#Write-Host $CertResponse.CertificateData

 

#Check if  a Cert was returned and process approiately

if ($CertResponse.CertificateData) {

    $CertFile = Savecertfile -CertificateData $CertResponse.CertificateData -Path ("C:\Scripts\IIS\") -Format $CertResponse.format -Filename $CertResponse.Filename

    #    $Password

    # Convert Password to PowerShell's Credential format

    $PWord = ConvertTo-SecureString -String $Password -AsPlainText -Force

    $PBLogon2 = 'Enter password below'

    $Credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $PBLogon2 , $PWord

 

    #$Pword = Get-Credential -UserName 'Enter password below' -Message 'Enter password below'

    $mypfx = Get-PfxData -FilePath "C:\Scripts\IIS\$($CertObj.CertName).pfx" -Password $Credential.Password

    Import-PFXCertificate -FilePath "C:\Scripts\IIS\$($CertObj.CertName).pfx" -CertStoreLocation cert:\LocalMachine\My -Password $Credential.Password

 

    #get-childitem -Path "C:\Scripts\IIS\$($CertObj.CertName).pfx"

    # Remove the PFX file

    remove-item -Path "C:\Scripts\IIS\$($CertObj.CertName).pfx"

    $CertObj.Successful = $true

}

<#

#Loop through the certs in Certificate store and write to log

$CertList = Get-ChildItem cert:\LocalMachine\My

$CertList | Out-File -Append -FilePath C:\Scripts\temp.txt

foreach ($Cert in $CertList) {

    #        $Cert.Thumbprint

    #        $Cert.Subject

    $Subject = $($Cert.Subject).ToLower()

    $CommonName = $("CN=" + $($CertObj.HostHeader) + "*").ToLower()

 

    if ($Subject -like $($($CommonName))) {

        $ThumbPrint = $Cert.Thumbprint

        "`r`nCert Subject: $($Subject)  Thumbprint: $($ThumbPrint)  NotBefore: $($cert.NotBefore)  NotAfter: $($Cert.NotAfter)  Serial Num: $($Cert.SerialNumber)"

        "`r`nCert Subject: $($Subject)  Thumbprint: $($ThumbPrint)  NotBefore: $($cert.NotBefore)  NotAfter: $($Cert.NotAfter)  Serial Num: $($Cert.SerialNumber)" | Out-File -Append -FilePath C:\Scripts\temp.txt

   }# If

 

}# foreach $cert

#>

# Remove the CA

Remove-theCAs

 

#add Log to object

$CertObj.CertLog = get-content -Path C:\Scripts\temp.txt

remove-item -Path "$($Global:HostingDrive)\INTERNAL_CAs\" -Recurse -force | Out-File -Append -FilePath  WSA:\$Global:ConsoleLog

 

return

 