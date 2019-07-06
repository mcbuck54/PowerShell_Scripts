[cmdletbinding()]

#requires -version 4

Param(

    [Parameter(Mandatory = $true, HelpMessage = "Required, The Certificate Object")]

    [PSObject]$SettingsObj

)

###########################################################

$ScriptName = "NewSite2_Settings"

$ScriptVersion = "2019.04.10"

$ScriptAuthor = "Marshall Buck"

$ScriptRevised = "04/10/2019"

$ScriptCreated = "03/13/2019"

 

 

$Global:Domain = $env:USERDOMAIN

$Global:IsThereARootCA = $False

$Global:HostingDrive = "F:"

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

"`r`nParameters Supplied to $($ScriptName) this time:"

"LOB:               $($SettingsObj.PlayBook.PB.WebSite.LOB)"

"Web Site Name:     $($SettingsObj.PlayBook.PB.WebSite.Name)"

"Release:           $($SettingsObj.PlayBook.PB.WebSite.Release)"

"TimeStamp:         $($SettingsObj.TimeStamp)"

"`r`n"

$WebSite = $($SettingsObj.PlayBook.PB.WebSite.Name)

<#

        $SettingsObj | Add-Member -MemberType NoteProperty -Name PlayBook        -Value $PlayBook

        $SettingsObj | Add-Member -MemberType NoteProperty -Name TimeStamp       -Value $Global:TimeStamp

        $SettingsObj | Add-Member -MemberType NoteProperty -Name SettingsLog     -Value "prefetch"

        $SettingsObj | Add-Member -MemberType NoteProperty -Name Successful      -Value $false

                   

 

#>

 

"$ScriptName Started at $($SettingsObj.TimeStamp)" | Out-File         -FilePath C:\Scripts\temp.txt

 

"`r`nParameters Supplied to $($ScriptName) this time:" | Out-File -Append -FilePath C:\Scripts\temp.txt

"LOB:               $($SettingsObj.PlayBook.PB.WebSite.LOB)" | Out-File -Append -FilePath C:\Scripts\temp.txt

"Web Site Name:     $($SettingsObj.PlayBook.PB.WebSite.Name)" | Out-File -Append -FilePath C:\Scripts\temp.txt

"Release:           $($SettingsObj.PlayBook.PB.WebSite.Release)" | Out-File -Append -FilePath C:\Scripts\temp.txt

"`r`n"

 

"CacheControl:            $($PlayBook.PB.WebSite.CustomHeaders.CacheControl)" | Out-File -Append -FilePath C:\Scripts\temp.txt

"CacheControlMaxAge:      $($PlayBook.PB.WebSite.CustomHeaders.CacheControlMaxAge)" | Out-File -Append -FilePath C:\Scripts\temp.txt

"ContentSecurityPolicy:   $($PlayBook.PB.WebSite.CustomHeaders.ContentSecurityPolicy)" | Out-File -Append -FilePath C:\Scripts\temp.txt

"ReferrerPolicy:          $($PlayBook.PB.WebSite.CustomHeaders.ReferrerPolicy)" | Out-File -Append -FilePath C:\Scripts\temp.txt

"StrictTransportSecurity: $($PlayBook.PB.WebSite.CustomHeaders.StrictTransportSecurity)" | Out-File -Append -FilePath C:\Scripts\temp.txt

"XContentTypeOptions:     $($PlayBook.PB.WebSite.CustomHeaders.XContentTypeOptions)" | Out-File -Append -FilePath C:\Scripts\temp.txt

"XXSSProtection:          $($PlayBook.PB.WebSite.CustomHeaders.CacheControl)" | Out-File -Append -FilePath C:\Scripts\temp.txt

 

# Settings below will be added to Web Site's Web.Config file in WebRoot

if (-not($WebSite)) {

    $SettingsObj.Successful = $False

    "$ScriptName Ended at $($SettingsObj.TimeStamp)" | Out-File -Append -FilePath C:\Scripts\temp.txt

    $SettingsObj.SettingsLog = Get-Content -Path C:\Scripts\temp.txt

    return

}# WebSite blank

 

#(1)        HTTP Strict Transport Security Header (HSTS)

#    Strict-Transport-Security enforces the use of HTTP over TLS/SSL. Properly using this header can help prevent man-in-the-middle attacks. HSTS header is defined in RFC 6797 (important - max age must be at least 86400).

#    Related to HSTS, applications teams must discontinue the use of http for https redirect at the application level, and perform the redirect with an iRule (or equivalent) F5 setup (infrastructure level)

#    Cigna Information Protection. Secure Coding Standard. Communication Security

#    27.03.02.09.c. Failed TLS connections must not fall back to an insecure connection

#    Initial value: Strict-Transport-Security: max-age=86400

if ($PlayBook.PB.WebSite.CustomHeaders.StrictTransportSecurity -ieq $true) {

    "Strict-Transport-Security set to 'max-age=31536000; includeSubDomains; preload'" | Out-File -Append -FilePath C:\Scripts\temp.txt

    C:\Windows\system32\inetsrv\appcmd.exe set config "$($Website)" -section:system.webServer/httpProtocol /+"customHeaders.[name='Strict-Transport-Security',value='max-age=31536000; includeSubDomains; preload']" | Out-File -Append -FilePath C:\Scripts\temp.txt

}

 

#(2)        Content Security Policy (CSP)

#    A properly configured Content-Security-Policy (CSP) can help prevent cross-site scripting (XSS) attacks by restricting the origins of JavaScript, CSS, and other potentially dangerous resources.

#    Cigna Information Protection. Secure Coding Standard. Input Validation

#    27.03.02.01.a. Conduct all data validation on a trusted system

#    27.03.02.01.b. (…) Validate all data from untrusted sources (e.g., databases, file streams, etc.)

#    27.03.02.01.j. Validate data from redirects (an attacker may submit malicious content directly to the target of the redirect, thus circumventing application logic and any validation performed before the redirect)

#    Initial value: Content-Security-Policy: script-src 'self'

#    Important: this header needs tuning; use Content-Security-Policy-Report-Only: for testing

if ($PlayBook.PB.WebSite.CustomHeaders.ContentSecurityPolicy -ieq $true) {

    "Content-Security-Policy set to 'default-src `"self`";script-src `"self`"'" | Out-File -Append -FilePath C:\Scripts\temp.txt

    C:\Windows\system32\inetsrv\appcmd.exe set config "$($Website)" -section:system.webServer/httpProtocol /+"customHeaders.[name='Content-Security-Policy',value='default-src "self";script-src "self"']" | Out-File -Append -FilePath C:\Scripts\temp.txt

}

 

 

#(3)        X-Content-Type-Options

#    Setting X-Content-Type-Options to "nosniff"� helps protect MIME or content sniffing. The only valid value for this field is “nosniff.”

#    Cigna Information Protection. Secure Coding Standard. Input Validation

#    27.03.02.01.k. Validate for expected data type

#    Initial value: X-Content-Type-Options: nosniff

if ($PlayBook.PB.WebSite.CustomHeaders.XContentTypeOptions -ieq $true) {

    "X-Content-Type-Options set to 'nosniff'" | Out-File -Append -FilePath C:\Scripts\temp.txt

    C:\Windows\system32\inetsrv\appcmd.exe set config "$($Website)" /section:system.webServer/httpProtocol /+customHeaders.["name='X-Content-Type-Options',value='nosniff'"] | Out-File -Append -FilePath C:\Scripts\temp.txt

}

 

#(4)        X-XSS-Protection

#    This http header sets the configuration for the cross-site scripting filter built in browsers.

#    Cigna Information Protection. Secure Coding Standard. Secure Coding Practices

#    27.03.01.a. Secure Coding Practices Applications must be designed and tested against the most common web threats and vulnerabilities, including, but not limited to: iii Cross-Site Scripting (XSS)

#    Initial value: X-Xss-Protection: 1; mode=block

if ($PlayBook.PB.WebSite.CustomHeaders.XXSSProtection -ieq $true) {

    "X-XSS-Protection set to '1;mode=block'" | Out-File -Append -FilePath C:\Scripts\temp.txt

    C:\Windows\system32\inetsrv\appcmd.exe set config "$($Website)" /section:system.webServer/httpProtocol /+customHeaders.["name='X-XSS-Protection',value='1;mode=block'"] | Out-File -Append -FilePath C:\Scripts\temp.txt

}

               

# (5)       X-Frame-Options (http/1.0)

#    Used to prevent browsers from framing site /  can defend against attacks like clickjacking.

#    Cigna Information Protection. Secure Coding Standard. Input Validation

#    27.03.02.01.j. Validate data from redirects (an attacker may submit malicious content directly to the target of the redirect, thus circumventing application logic and any validation performed before the redirect)

#    Initial value: x-frame-options: SAMEORIGIN

if ($PlayBook.PB.WebSite.CustomHeaders.XFrameOptions -ieq $true) {

    "X-Frame-Options set to 'SAMEORIGIN'" | Out-File -Append -FilePath C:\Scripts\temp.txt

    C:\Windows\system32\inetsrv\appcmd.exe set config "$($Website)" /section:system.webServer/httpProtocol /+customHeaders.["name='X-Frame-Options',value='SAMEORIGIN'"] | Out-File -Append -FilePath C:\Scripts\temp.txt

}

 

# (6)       Referrer-Policy

#    Allows a site to control how much information the browser includes with navigations away from a document.

#    Cigna Information Protection. Secure Coding Standard. Data Protection

#    27.03.02.08.h. Do not include sensitive data in HTTP GET request parameters

#    Initial value: Referrer-Policy: no-referrer-when-downgrade

if ($PlayBook.PB.WebSite.CustomHeaders.ReferrerPolicy -ieq $true) {

    "Referrer-Policy set to 'no-referrer-when-downgrade'" | Out-File -Append -FilePath C:\Scripts\temp.txt

    C:\Windows\system32\inetsrv\appcmd.exe set config "$($Website)" /section:system.webServer/httpProtocol /+customHeaders.["name='Referrer-Policy',value='no-referrer-when-downgrade'"] | Out-File -Append -FilePath C:\Scripts\temp.txt

}

 

#(7)        Cache-Control (http 1.1) or Expires (http 1.0)

#             Cigna Information Protection. Secure Coding Standard. Data Protection

#             27.03.02.08.j. Disable client side caching on pages containing sensitive data. Cache-Control: no-store, may be used in conjunction with the HTTP header control "Pragma: no-cache", which is less effective, but is HTTP/1.0 backward compatible

#             Initial value: Cache-Control: max-age=900

 

  

if (($PlayBook.PB.WebSite.CustomHeaders.CacheControl -ieq $true) -and `

    ($PlayBook.PB.WebSite.CustomHeaders.CacheControlMaxAge -ieq $false)) {

    "Cache-Control set to 'no-cache,no-store'" | Out-File -Append -FilePath C:\Scripts\temp.txt

    C:\Windows\system32\inetsrv\appcmd.exe set config "$($Website)" /section:system.webServer/httpProtocol /+customHeaders.["name='Cache-Control',value='no-cache,no-store'"] | Out-File -Append -FilePath C:\Scripts\temp.txt

}

 

if (($PlayBook.PB.WebSite.CustomHeaders.CacheControl -ieq $false) -and `

    ($PlayBook.PB.WebSite.CustomHeaders.CacheControlMaxAge -ieq $true)) {

    "Cache-Control set to 'max-age=900'" | Out-File -Append -FilePath C:\Scripts\temp.txt

    C:\Windows\system32\inetsrv\appcmd.exe set config "$($Website)" /section:system.webServer/httpProtocol /+customHeaders.["name='Cache-Control',value='max-age=900'"] | Out-File -Append -FilePath C:\Scripts\temp.txt

}

 

if (($PlayBook.PB.WebSite.CustomHeaders.CacheControl -ieq $true) -and `

    ($PlayBook.PB.WebSite.CustomHeaders.CacheControlMaxAge -ieq $true)) {

    "Cache-Control and Cache-ControlMaxAge selected so it is set to 'max-age=900'" | Out-File -Append -FilePath C:\Scripts\temp.txt

    C:\Windows\system32\inetsrv\appcmd.exe set config "$($Website)" /section:system.webServer/httpProtocol /+customHeaders.["name='Cache-Control',value='max-age=900'"] | Out-File -Append -FilePath C:\Scripts\temp.txt

}

 

#             These field(s) set conditions for storing data in the browser cache.

#             Expires header is defined Section 5.3 of RFC 7234 (RFC 723 Section 7.1.1.1 for date format;

#             Cache-control is defined in RFC 7234. We recommend the use of the cache-control header it must contain at least one of the following records:

#             no-store; public, max-age = N; and private, max-age = N (where N is any integer greater than zero).

#             For more information about this header, see Google’s best practice guide.

 

#add Log to object

$SettingsObj.Successful = $True

"$ScriptName Ended at $($SettingsObj.TimeStamp)" | Out-File -Append -FilePath C:\Scripts\temp.txt

$SettingsObj.SettingsLog = Get-Content -Path C:\Scripts\temp.txt

Return

