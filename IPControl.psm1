#Using Module .\Classes.psm1
$InformationPreference = 'Continue'
$ErrorActionPreference = 'Stop'

Function Connect-IPControl {
    <#
    .SYNOPSIS
    Connects to the API of an IPControl instance

    .DESCRIPTION
    Connects to the API of an IPControl instance. The session details are then set to global variable $ipcontrol_session.

    .PARAMETER Instance
    Mandatory string thatspecifies the hostname of the IPControl instance. For example: ipcontrol.contoso.com

    .PARAMETER Port
    Optional int32 port of the IPControl instance. The default is 8443.

    .PARAMETER Proxy
    Optional string that specifies a proxy. The format should be: 'http://x.x.x.x:8888' where x.x.x.x is the ip or hostname of the proxy server. Proxy credentials are not supported yet. Caution: Using this setting will force all certificate checks to be disabled. It is equivalent to the -NotSecure function.

    .PARAMETER AccessToken
    Optionally specify the access token manually.

    .PARAMETER User
    Specifies the user connecting to the API only if you want to enter it on the command line manually. If you do not specify this, you will be prompted for it.

    .PARAMETER SecurePass
    Specifies the Secure Password for connecting to the API only if you want to enter it on the command line manually. If you do not specify this, you will be prompted for it. Use ConvertTo-SecureString to create the needed object for this parameter.

    .PARAMETER Quiet
    Switch parameter to silence the output of the session details upon login.

    .PARAMETER SkipPreviousSessionCheck
    Switch parameter to override the requirement to disconnect from a previous session before starting a new session on a different instance.

    .INPUTS
    None. You cannot pipe objects to Connect-IPControl.

    .OUTPUTS
    A table showing the pertinent details of your session will be sent to the host. Disable this with -Quiet.

    .EXAMPLE
    Standard logon. Be prompted for credential manually.

    Connect-IPControl -Instance 'ipcontrol.contoso.com'

    .EXAMPLE
    Connect with a secure password that you enter beforehand.
    
    $secure_pass = Read-Host -AsSecureString
    Connect-IPControl -Instance 'ipcontrol.contoso.com' -User 'username' -SecurePass $secure_pass

    .EXAMPLE
    Connect with an access token.

    Connect-IPControl -Instance 'ipcontrol.contoso.com' -AccessToken 'ey...'

    .NOTES

    #>
    [OutputType([string])]
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Instance,
        [Parameter(Mandatory = $true, ParameterSetName = 'AccessToken')]
        [string]$AccessToken,
        [Parameter(Mandatory = $true, ParameterSetName = 'Credential')]
        [string]$User,
        [Parameter(Mandatory = $true, ParameterSetName = 'Credential')]
        [SecureString]$SecurePass,
        [Parameter(Mandatory = $false)]
        [switch]$SkipPreviousSessionCheck,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int32]$Port = 8443,
        [Parameter(Mandatory = $false)]
        [ValidateScript({ $_ -match '^http[s]{0,}://.{1,}:[0-9]{2,5}$' })]
        [string]$Proxy,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    Function New-IPControlAuthenticationProperties {
        [OutputType([hashtable])]
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $true)]
            [string]$User,
            [Parameter(Mandatory = $true)]
            [securestring]$SecurePass,
            [Parameter(Mandatory = $false)]
            [string]$Proxy
        )
        [hashtable]$parameters = @{}
        If ($PSVersionTable.PSVersion.Major -ge 7) {
            [string]$encrypted_string = $SecurePass | ConvertFrom-SecureString -AsPlainText
        }
        Else {
            [string]$encrypted_string = ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePass)))
        }
        [string]$Body = "username=$User&password=$encrypted_string"
        $parameters.Add('Body', $Body)
        Remove-Variable -Name Body
        [string]$login_url = ($Protocol + '://' + $Instance + ':' + $Port + '/inc-rest/api/v1/login')
        [int32]$ps_version_major = $PSVersionTable.PSVersion.Major
        If ($ps_version_major -eq 5) {
            # The below C# code provides the equivalent of the -SkipCertificateCheck parameter for Windows PowerShell 5.1 Invoke-WebRequest
            If (($null -eq ("TrustAllCertsPolicy" -as [type])) -and ($Protocol -eq 'http')) {
                [string]$certificate_policy = @"
                using System.Net;
                using System.Security.Cryptography.X509Certificates;
                public class TrustAllCertsPolicy : ICertificatePolicy {
                    public bool CheckValidationResult(
                        ServicePoint srvPoint, X509Certificate certificate,
                        WebRequest request, int certificateProblem) {
                        return true;
                    }
                }
"@
                $Error.Clear()
                Try {
                    Add-Type -TypeDefinition $certificate_policy
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Add-Type failed to add the custom certificate policy due to [$Message]"
                    Break
                }
                $Error.Clear()
                Try {
                    [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "New-Object failed to create a new 'TrustAllCertsPolicy' CertificatePolicy object due to [$Message]."
                    Break
                }
            }
            $parameters.Add('UseBasicParsing', $true)
        }
        ElseIf ( $ps_version_major -gt 5) {
            $parameters.Add('SkipCertificateCheck', $true)
        }
        Else {
            Write-Warning -Message "Please use either Windows PowerShell 5.1 or PowerShell Core."
            Break
        }
        $parameters.Add('Uri', $login_url)
        $parameters.Add('Method', 'POST')
        If ($Proxy.Length -gt 0) {
            $parameters.Add('Proxy', $Proxy)
        }
        $parameters.Add('ContentType', 'application/json')
        $Error.Clear()
        Try {
            [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject]$results = Invoke-WebRequest @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            If ($Message -match '(The underlying connection was closed|The SSL connection could not be established)') {
                Write-Warning -Message 'Please try again with the -NotSecure parameter if you are connecting to an insecure instance.'
                Break
            }
            ElseIf ($Message -match 'Response status code does not indicate success:') {
                $Error.Clear()
                Try {
                    [int32]$return_code = $Message -split 'success: ' -split ' ' | Select-Object -Last 1 -Skip 1
                }
                Catch {
                    [string]$Message2 = $_.Exception.Message
                    Write-Warning -Message "Unable to extract the error code from [$Message] due to [$Message2]"
                }
            }
            ElseIf ($Message -match 'The remote server returned an error: ') {
                $Error.Clear()
                Try {
                    [int32]$return_code = $Message -split '\(' -split '\)' | Select-Object -Skip 1 -First 1
                }
                Catch {
                    [string]$Message2 = $_.Exception.Message
                    Write-Warning -Message "Unable to extract the error code from [$Message] due to [$Message2]"
                }
            }
            ElseIf ($Message -eq 'An error occurred while sending the request.') {
                Write-Warning -Message "Received the error message '$Message' - This usually means something is wrong with the server! Contact your admins."
                Break
            }
            Else {
                [string]$ReturnCodeWarning = "Invoke-WebRequest failed for an unexpected reason due to [$Message]"
                Write-Warning -Message $ReturnCodeWarning
                Break
            }
            [string]$ReturnCodeWarning = Switch ($return_code) {
                401 { "You received HTTP Code $return_code (Unauthorized). DID YOU MAYBE ENTER THE WRONG PASSWORD? :-)" }
                403 { "You received HTTP Code $return_code (Forbidden). DO YOU MAYBE NOT HAVE PERMISSION TO THIS? [$command]" }
                404 { "You received HTTP Code $return_code (Page Not Found). ARE YOU SURE THIS ENDPOINT REALLY EXISTS? [$command]" }
                Default { "You received HTTP Code $return_code instead of '200 OK'. Apparently, something is wrong..." }
            }
            Write-Warning -Message $ReturnCodeWarning
            Break
        }
        [string]$content_json = $results.Content
        If ($content_json -notmatch '^{"') {
            Write-Warning -Message "The returned content does not appear to be valid. How did this happen?"
            Break
        }
        $Error.Clear()
        Try {
            [PSCustomObject]$token_properties = $content_json | ConvertFrom-Json
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "ConvertFrom-Json failed due to [$Message]."
            Break
        }
        Return $token_properties
    }
    If ($Instance -match '^http[s]{0,}://') {
        Write-Warning -Message "Please do not include https:// in the name of the instance. See Get-Help Connect-IPControl -Examples for examples."
        Break
    }
    If ($NotSecure -eq $true) {
        [string]$protocol = 'http'
    }
    Else {
        [string]$protocol = 'https'
    }
    If (($ipcontrol_session.ExpirationDate -is [datetime]) -and ($SkipPreviousSessionCheck -ne $true)) {
        [datetime]$current_date = Get-Date
        [datetime]$expiration_date = $ipcontrol_session.ExpirationDate
        [timespan]$TimeRemaining = ($expiration_date - $current_date)
        [int32]$SecondsRemaining = $TimeRemaining.TotalSeconds
        If ($SecondsRemaining -gt 60) {
            [string]$AlreadyConnectedInstance = ($ipcontrol_session.Instance)
            If ($Instance -eq $AlreadyConnectedInstance) {
                Write-Warning -Message "Please use Disconnect-IPControl to disconnect from $AlreadyConnectedInstance before connecting to $Instance (Use -SkipPreviousSessionCheck to override this)"
            }
            Else {
                Write-Warning -Message "Please use Disconnect-IPControl to disconnect your active connection to $AlreadyConnectedInstance (It still has [$SecondsRemaining] seconds remaining) (Use -SkipPreviousSessionCheck to override this)"
            }
            Break
        }
        Else {
            If ($expiration_date -gt (Get-Date -Date '1970-01-01 00:00:00')) {
                If ($SecondsRemaining -lt -172800) {
                    [int32]$DaysRemaining = ($SecondsRemaining * -1) / 86400
                    Write-Warning -Message "Your previous token expired about $DaysRemaining days ago on $expiration_date. Cleaning up the previous session."
                }
                ElseIf ($SecondsRemaining -lt -7200) {
                    [int32]$HoursRemaining = ($SecondsRemaining * -1) / 3600
                    Write-Warning -Message "Your previous token expired about $HoursRemaining hours ago on $expiration_date. Cleaning up the previous session."
                }
                ElseIf ($SecondsRemaining -lt -300) {
                    [int32]$MinutesRemaining = ($SecondsRemaining * -1) / 60
                    Write-Warning -Message "Your previous token expired about $MinutesRemaining minutes ago on $expiration_date. Cleaning up the previous session."
                }
                Else {
                    [int32]$SecondsRemaining = $SecondsRemaining * -1
                    Write-Warning -Message "Your previous token expired about $SecondsRemaining seconds ago on $expiration_date. Cleaning up the previous session."
                }
            }
            $Error.Clear()
            Try {
                Remove-Variable -Name ipcontrol_session -Scope Global -Force
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Remove-Variable failed to remove the expired `$ipcontrol_session variable due to [$Message]."
                Break
            }
        }
    }
    If ($AccessToken.Length -eq 0) {
        If ($User.Length -eq 0 ) {
            $Error.Clear()
            Try {
                [string]$User = Read-Host -Prompt 'Please enter username (e.g. jsmith)'
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Read-Host failed to receive the current username due to [$Message]."
                Break
            }
            If ($User.Length -eq 0) {
                Write-Warning -Message 'You needed to specify a username. Please try again.'
                Break
            }
        }
        If ($SecurePass.Length -eq 0 ) {
            $Error.Clear()
            Try {
                [SecureString]$SecurePass = Read-Host -Prompt 'Please enter password (e.g. ******)' -AsSecureString
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Read-Host failed due to [$Message]."
                Break
            }
        }
        [hashtable]$parameters = @{}
        $parameters.Add('User', $User)
        $parameters.Add('SecurePass', $SecurePass)
        If ($Proxy.Length -gt 0) {
            $parameters.Add('Proxy', $Proxy)
        }
        $Error.Clear()
        Try {
            [PSCustomObject]$auth_response = New-IPControlAuthenticationProperties @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "New-IPControlAuthenticationProperties failed due to [$Message]."
            Break
        }
        [string]$AccessToken = $auth_response.access_token
    }
    [datetime]$current_date = Get-Date
    [datetime]$expiration_date = $current_date.AddHours(1)
    [hashtable]$header = @{'Authorization' = "Bearer $AccessToken"; }
    [hashtable]$ipcontrol_session = @{}
    $ipcontrol_session.Add('User', $User)
    $ipcontrol_session.Add('Instance', $Instance)
    If ($NotSecure -eq $true) {
        $ipcontrol_session.Add('NotSecure', $True)
    }
    If ($Proxy.Length -gt 0) {
        $ipcontrol_session.Add('Proxy', $Proxy)
    }
    $ipcontrol_session.Add('ExpirationDate', $expiration_date)
    $ipcontrol_session.Add('AccessToken', $AccessToken)
    $ipcontrol_session.Add('Header', $Header)
    $ipcontrol_session.Add('Port', $Port)
    $Error.Clear()
    Try {
        New-Variable -Name 'ipcontrol_session' -Scope Global -Value $ipcontrol_session -Force
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "New-Variable failed to create the session properties object due to [$Message]"
        Break
    }
    Write-Verbose -Message 'Global variable $ipcontrol_session.header has been set. Refer to this as your authentication header.'
    $ipcontrol_session.Add('Protocol', $Protocol)
    [PSCustomObject]$ipcontrol_session_display = [PSCustomObject]@{ Protocol = $protocol; Instance = $Instance; Port = $Port; TokenExpires = $expiration_date; User = $User; AccessToken = ($AccessToken.SubString(0, 5) + '..' + $AccessToken.SubString(($AccessToken.Length - 5), 5)) }
    If ($Quiet -ne $true) {
        Format-Table -InputObject $ipcontrol_session_display -AutoSize -Wrap
    }
}

Function ConvertTo-QueryString {
    <#
    Credit for this function: https://www.powershellgallery.com/packages/MSIdentityTools
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter(Mandatory = $true)]
        [System.Collections.Specialized.OrderedDictionary]$InputObject
    )
    Process {
        $QueryString = New-Object System.Text.StringBuilder
        ForEach ($Item in $InputObject.GetEnumerator()) {
            If ($QueryString.Length -gt 0) { [void]$QueryString.Append('&') }
            [string]$ParameterName = $Item.Key
            If ($Item.value -is [boolean]) {
                If ($Item.value -eq $true) {
                    [void]$QueryString.AppendFormat('{0}={1}', $ParameterName, [System.Net.WebUtility]::UrlEncode('true'))
                }
                Else {
                    [void]$QueryString.AppendFormat('{0}={1}', $ParameterName, [System.Net.WebUtility]::UrlEncode('false'))
                }
            }
            Else {
                [void]$QueryString.AppendFormat('{0}={1}', $ParameterName, [System.Net.WebUtility]::UrlEncode($Item.value))
            }
        }
        [string]$Result = $QueryString.ToString()
        Write-Output $Result
    }
}

Function Invoke-IPControlAPI {
    <#
    .SYNOPSIS
    Invokes the API of an IPControl instance

    .DESCRIPTION
    The `Invoke-IPControlAPI` cmdlet sends API commands (in the form of HTTPS requests) to an instance of IPControl. It returns the results in either JSON or PSCustomObject.

    .PARAMETER Command
    Specifies the command to invoke with the API call. The value must begin with a forward slash. For example: '/Gets/getDeviceByIPAddr'

    .PARAMETER Method
    Specifies the method to use with the API call. Valid values are GET and POST.

    .PARAMETER NotSecure
    Switch parameter to accomodate instances using the http protocol. Only use this if the instance is on http and not https.

    .PARAMETER Body
    The Body string. Use ConvertTo-QueryString to URL-encode your body parameters.

    .PARAMETER ContentType
    Specifies the content type of the body (only needed if a body is included)

    .PARAMETER Instance
    Specifies the name of the IPControl instance. For example: ipcontrol.contoso.com

    .PARAMETER JustGiveMeJSON
    Switch parameter to return the results in a JSON string instead of a PSCustomObject

    .INPUTS
    None. You cannot pipe objects to Invoke-IPControlAPI (yet).

    .OUTPUTS
    The reponse is provided in a PSCustomObject.

    .EXAMPLE
    Invoke-IPControlAPI -Command '/Gets/getDeviceByIPAddr' -Method GET -Body getDeviceByIPAddr?ipAddress=1.2.3.4

    .NOTES
    You must use Connect-IPControl to establish the token by way of global variable.

    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Command,
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,
        [Parameter(Mandatory = $false)]
        [switch]$NotSecure,
        [Parameter(Mandatory = $false)]
        [string]$Body,
        [Parameter(Mandatory = $false)]
        [string]$ContentType = 'application/x-www-form-urlencoded; charset=UTF-8', # 'application/json',
        [Parameter(Mandatory = $false)]
        [string]$Instance,
        [Parameter(Mandatory = $false)]
        [switch]$JustGiveMeJSON
    )
    If ($ipcontrol_session.Instance.Length -eq 0) {
        Write-Warning -Message "Please use Connect-IPControl to establish your access token."
        Break
    }
    ElseIf ($ipcontrol_session.header.Authorization -notmatch '^Bearer [a-zA-Z-_:,."0-9]{1,}$') {
        [string]$malformed_token = $ipcontrol_session.header.values
        Write-Warning -Message "Somehow the access token is not in the expected format. Please contact the author with this apparently malformed token: $malformed_token"
        Break
    }
    ElseIf ($command -notmatch '^/.{1,}') {
        Write-Warning -Message "Please prefix the command with a forward slash (for example: /?)."
        Break
    }
    [int32]$Port = $ipcontrol_session.Port
    If ($Instance.Length -eq 0) {
        [string]$Instance = $ipcontrol_session.Instance
    }
    [hashtable]$parameters = @{}
    If ($NotSecure -eq $true) {
        [string]$protocol = 'http'
    }
    Else {
        [string]$protocol = 'https'
    }
    [int64]$ps_version_major = $PSVersionTable.PSVersion.Major
    $parameters.Add('UseBasicParsing', $true)
    If ($ps_version_major -gt 5) {
        If ($protocol -eq 'http') {
            $parameters.Add('SkipCertificateCheck', $true)
        }
    }
    If ($ps_version_major -lt 5) {
        Write-Warning -Message "Please use either Windows PowerShell 5.x or PowerShell Core. This module is not compatible with Windows PowerShell below version 5."
        Break
    }
    [string]$api_url = ($Protocol + '://' + $Instance + ':' + $Port + '/inc-rest/api/v1' + $command)
    If ($Body.Length -gt 0) {
        Write-Verbose -Message "Sending body: $Body"
        If ($Method -eq 'GET') {
            [string]$api_url = $api_url + '?' + $Body
        }
        Else {
            $parameters.Add('Body', $Body)
        }
    }
    $parameters.Add('Uri', $api_url)
    $parameters.Add('Method', $Method)
    $parameters.Add('ContentType', $ContentType)
    If ($null -ne $ipcontrol_session.Header) {
        $parameters.Add('Headers', $ipcontrol_session.Header) # @($ipcontrol_session.Header)) , @{'Accept' = 'application/json'}
    }
    Else {
        Write-Warning -Message "How is it that the `$ipcontrol_session global variable does not contain a header?"
        Break
    }
    If ($ipcontrol_session.Proxy.Length -gt 0) {
        $parameters.Add('Proxy', $ipcontrol_session.Proxy)
        [int32]$ps_version_major = $PSVersionTable.PSVersion.Major
        If ($ps_version_major -eq 5) {
            # The below C# code provides the equivalent of the -SkipCertificateCheck parameter for Windows PowerShell 5.1 Invoke-WebRequest
            If (($null -eq ("TrustAllCertsPolicy" -as [type])) -and ($Protocol -eq 'http')) {
                [string]$certificate_policy = @"
                using System.Net;
                using System.Security.Cryptography.X509Certificates;
                public class TrustAllCertsPolicy : ICertificatePolicy {
                    public bool CheckValidationResult(
                        ServicePoint srvPoint, X509Certificate certificate,
                        WebRequest request, int certificateProblem) {
                        return true;
                    }
                }
"@
                $Error.Clear()
                Try {
                    Add-Type -TypeDefinition $certificate_policy
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Add-Type failed to add the custom certificate policy due to [$Message]"
                    Break
                }
                $Error.Clear()
                Try {
                    [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "New-Object failed to create a new 'TrustAllCertsPolicy' CertificatePolicy object due to [$Message]."
                    Break
                }
            }
            $parameters.Add('UseBasicParsing', $true)
        }
        ElseIf ( $ps_version_major -gt 5) {
            $parameters.Add('SkipCertificateCheck', $true)
        }
        Else {
            Write-Warning -Message "Please use either Windows PowerShell 5.1 or PowerShell Core."
            Break
        }
    }
    [string]$parameters_debug_display = $parameters | ConvertTo-Json
    Write-Debug -Message "Sending the following parameters to $api_url -> $parameters_debug_display."
    [string]$parameters_verbose_display = $parameters | Select-Object -ExcludeProperty $Headers | ConvertTo-Json
    Write-Verbose -Message "Sending the following parameters to $api_url -> $parameters_verbose_display."
    $ProgressPreference = 'SilentlyContinue'
    $Error.Clear()
    Try {
        [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject]$results = Invoke-WebRequest @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        If ($Message -match '(The underlying connection was closed|The SSL connection could not be established)') {
            Write-Warning -Message 'Please try again with the -NotSecure parameter if you are connecting to an insecure instance.'
            Break
        }
        ElseIf ($Message -match 'Response status code does not indicate success:') {
            $Error.Clear()
            Try {
                [int32]$return_code = $Message -split 'success: ' -split ' ' | Select-Object -Last 1 -Skip 1
            }
            Catch {
                [string]$Message2 = $_.Exception.Message
                Write-Warning -Message "Unable to extract the error code from [$Message] due to [$Message2]"
                Break
            }
        }
        ElseIf ($Message -match 'The remote server returned an error: ') {
            $Error.Clear()
            Try {
                [int32]$return_code = $Message -split '\(' -split '\)' | Select-Object -Skip 1 -First 1
            }
            Catch {
                [string]$Message2 = $_.Exception.Message
                Write-Warning -Message "Unable to extract the error code from [$Message] due to [$Message2]"
                Break
            }
        }
        Else {
            [string]$ReturnCodeWarning = "Invoke-WebRequest failed for unknown reasons under Invoke-IPControlAPI due to [$Message]. This is not normal (at this point) to fail like this so you should check for possible performance problems on the IPControl instance or something else unexpected. Here are the parameters that were sent: $parameters_debug_display"
            Write-Warning -Message $ReturnCodeWarning
            Break
        }
        If ($return_code -gt 0) {
            [string]$ReturnCodeWarning = Switch ($return_code) {
                401 { "You received HTTP Code $return_code (Unauthorized). HAS YOUR TOKEN EXPIRED? ARE YOU ON THE CORRECT DOMAIN? :-)" }
                403 { "You received HTTP Code $return_code (Forbidden). DO YOU MAYBE NOT HAVE PERMISSION TO THIS? [$command]" }
                404 { "You received HTTP Code $return_code (Page Not Found). ARE YOU SURE THIS ENDPOINT REALLY EXISTS? [$command]" }
                Default { "You received HTTP Code $return_code instead of '200 OK'. Apparently, something is wrong..." }
            }
            Write-Warning -Message $ReturnCodeWarning
            Break
        }
    }
    $ProgressPreference = 'Continue'
    [string]$content = $results.Content
    If ($JustGiveMeJSON -eq $true) {
        Return $content
    }
    $Error.Clear()
    Try {
        [PSCustomObject]$content_object = $content | ConvertFrom-JSON
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "ConvertFrom-JSON failed to convert the returned results due to [$Message]."
        Break
    }
    Return $content_object
}

Function Get-IPControlDevice {
    <#
    
    .SYNOPSIS
    Gets a device (a.k.a. an IP address) from an IPControl instance

    .DESCRIPTION
    Gets a device (a.k.a. an IP address) from an IPControl instance

    .PARAMETER IPAddress
    Mandatory string representing the device (IP address) to look up.

    .INPUTS
    None. You cannot pipe objects to Invoke-IPControlAPI (yet).

    .OUTPUTS
    The reponse is provided in a PSCustomObject.

    .EXAMPLE
    Invoke-IPControlAPI -Command '/Gets/getDeviceByIPAddr' -Method GET -Body getDeviceByIPAddr?ipAddress=1.2.3.4

    .NOTES
    You must use Connect-IPControl to establish the token by way of global variable.

    #>
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    Param(
        [ValidateScript({ $_ -match '^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$' })]
        [Parameter(Mandatory = $true)]
        [string]$IPAddress
    )
    [string]$Command = '/Gets/getDeviceByIPAddr'
    [string]$Method = 'GET'
    [hashtable]$parameters = @{}
    [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
    $BodyMetaData.Add('ipAddress', $IPAddress)
    [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
    $parameters.Add('Body', $Body)
    $parameters.Add('Method', $Method)
    $parameters.Add('Command', $Command)
    $Error.Clear()
    Try {
        [PSCustomObject[]]$results = Invoke-IPControlAPI @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Invoke-IPControlAPI failed to execute [$Command] on [$Instance] due to [$Message]."
        Break
    }
    If ($results.Count -gt 0) {
        Return $results
    }
}