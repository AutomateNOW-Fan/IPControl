Using Module .\Classes.psm1
$InformationPreference = 'Continue'
$ErrorActionPreference = 'Stop'

#Region = Authentication Functions =

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
    Connect with a secure password that you genereated beforehand.

    $secure_pass = Read-Host -AsSecureString
    Connect-IPControl -Instance 'ipcontrol.contoso.com' -User 'username' -SecurePass $secure_pass

    .EXAMPLE
    Connect via access token.

    Connect-IPControl -Instance 'ipcontrol.contoso.com' -AccessToken 'ey...'

    .NOTES

    #>
    [OutputType([string])]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
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
        If ($AccessToken.Length -eq 0) {
            Write-Warning -Message "Somehow the received access token was empty!"
            Break
        }
    }
    # Note - it is neccessary to extract the user name and expiration date from the access token
    [string]$access_token_info_encoded = $AccessToken -split '\.' | Select-Object -Skip 1 -First 1
    If ($access_token_info_encoded -notmatch '^[A-Za-z0-9+/]+={0,2}$') {
        Write-Warning -Message "Somehow the access token was not in the expected format."
        Break
    }
    [int32]$access_token_info_encoded_length = $access_token_info_encoded.Length
    [int32]$access_token_base64_divisor = $access_token_info_encoded_length % 4
    If ($access_token_base64_divisor -eq 1) {
        Write-Warning -Message "Somehow this string ($access_token_info_encoded) doesn't obey the laws of Base64 encoding!"
        Break
    }
    Switch ($access_token_base64_divisor) {
        3 { [string]$base64_padding = '=' }
        2 { [string]$base64_padding = '==' }
    }
    [string]$access_token_info_encoded += $base64_padding
    $Error.Clear()
    Try {
        [string]$access_token_info_json = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($access_token_info_encoded))
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Somehow the details from this encoded token could not be converted from Base64 format: $AccessToken due to $Message"
        Break
    }
    $Error.Clear()
    Try {
        [PSCustomObject]$access_token_object = $access_token_info_json | ConvertFrom-JSON
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "ConvertFrom-JSON failed to convert the decoded access token json string due to [$Message]."
        Break
    }
    [string]$User = $access_token_object.adminLogin
    If ($User.Length -eq 0) {
        Write-Warning -Message "Somehow the user name to which this token was issued could not be derived."
        Break
    }
    [int64]$expiration_date_unix = $access_token_object.exp
    If ($expiration_date_unix -eq 0) {
        Write-Warning -Message "Somehow the expiration date of this token could not be derived."
        Break
    }
    $Error.Clear()
    Try {
        [System.TimeZoneInfo]$timezone = Get-TimeZone
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Get-TimeZone failed to get the local time zone due to [$Message]."
        Break
    }
    [boolean]$dst = (Get-Date).IsDaylightSavingTime()
    If ($dst -eq $true) {
        [System.TimeSpan]$utc_offset = ($timezone.BaseUtcOffset + (New-TimeSpan -Minutes 60))
    }
    Else {
        [System.TimeSpan]$utc_offset = $timezone.BaseUtcOffset
    }
    [datetime]$expiration_date_utc = (Get-Date -Date '1970-01-01').AddSeconds($expiration_date_unix)
    [datetime]$expiration_date = $expiration_date_utc + $utc_offset
    [hashtable]$header = @{'Authorization' = "Bearer $AccessToken"; 'Accept' = 'application/json' }
    [hashtable]$ipcontrol_session = @{}
    $ipcontrol_session.Add('TokenInfo', $access_token_object)
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
    [PSCustomObject]$ipcontrol_session_display = [PSCustomObject]@{ Protocol = $protocol; Instance = $Instance; Port = $Port; TokenExpires = $expiration_date; User = $User; AccessToken = ($AccessToken.SubString(0, 4) + '..' + $AccessToken.SubString(($AccessToken.Length - 5), 5)) }
    If ($Quiet -ne $true) {
        Format-Table -InputObject $ipcontrol_session_display -AutoSize -Wrap
    }
}

Function Disconnect-IPControl {
    <#
    .SYNOPSIS
    Disconnects from the API of an IPControl instance

    .DESCRIPTION
    The `Disconnect-IPControl` function removes the global session variable object allowing a new one to be set.

    .INPUTS
    None. You cannot pipe objects to Disconnect-IPControl.

    .OUTPUTS
    A string indicating the results of the disconnection attempt.

    .EXAMPLE
    Disconnect-IPControl

    .NOTES
    The main purpose of this function is to remove the global session variable $ipcontrol_session

    #>
    [CmdletBinding()]
    Param(
    )
    If ($null -eq $ipcontrol_session.Instance) {
        Write-Warning -Message "You are not actually connected so you can't disconnect"
        Break
    }
    [datetime]$ExpirationDate = $ipcontrol_session.ExpirationDate
    $Error.Clear()
    Try {
        Remove-Variable -Name ipcontrol_session -Scope Global -Force
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Remove-Variable failed to remove the expired ipcontrol_session global variable (under Disconnect-IPControl) due to [$Message]."
        Break
    }
    If ($ExpirationDate -gt (Get-Date -Date '1970-01-01 00:00:00')) {
        [datetime]$current_date = Get-Date
        [timespan]$TimeRemaining = ($ExpirationDate - $current_date)
        [int32]$SecondsRemaining = $TimeRemaining.TotalSeconds
        If ($SecondsRemaining -lt 2) {
            Write-Information -MessageData "Removed the already expired `$ipcontrol_session global variable from this session"
        }
        Else {
            Write-Information -MessageData "Removed the non-expired `$ipcontrol_session global variable from this session (it had $SecondsRemaining seconds remaining)"
        }
    }
}

Function Confirm-IPControlSession {
    [OutputType([boolean])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    [datetime]$current_date = Get-Date
    [datetime]$ipcontrol_session_expiration_date = $ipcontrol_session.ExpirationDate
    If ($current_date -lt $ipcontrol_session_expiration_date) {
        Return $true
    }
    Else {
        [timespan]$token_elapsed_duration = $current_date - $ipcontrol_session_expiration_date
        [int32]$token_minutes_elapsed = $token_elapsed_duration.TotalMinutes
        If ($token_minutes_elapsed -gt 1) {
            Write-Warning -Message "Your current IPControl token expired about $token_minutes_elapsed minutes ago"
        }
        ElseIf ($token_minutes_elapsed -eq 1) {
            Write-Warning -Message "Your current IPControl token expired about 1 minute ago"
        }
        Else {
            Write-Warning -Message "Your current IPControl token expired less than 1 minute ago"
        }
        Return $false
    }
}

#EndRegion

#Region = Object Functions =

#region - Containers

Function Get-IPControlContainer {
    <#

    .SYNOPSIS
    Gets a Container from an IPControl instance

    .DESCRIPTION
    Gets a Container from an IPControl instance

    .PARAMETER Name
    String representing the Name of the Container to look up.

    .PARAMETER Id
    Int64 representing the Id of the Container to look up.

    .PARAMETER Device
    [Device] object from which the Container name can be derived.

    .PARAMETER Parent
    Switch that will cause of the parent of the target Container to be returned instead of the target Container

    .INPUTS
    Container names and [Device] objects can be sent across the pipeline.

    .OUTPUTS
    The reponse is provided in a [Container] class object.

    .EXAMPLE
    Gets a Container by name

    Get-IPControlContainer -Name '/IPControl/Contoso/Container1'

    .EXAMPLE
    Gets a Container by its IPControl Id

    Get-IPControlContainer -Id 39495

    .EXAMPLE
    Gets the parent Container of a Container by name

    Get-IPControlContainer -Name '/IPControl/Contoso/Container1' -Parent

    .NOTES
    You must use Connect-IPControl to establish a connection and define the global session variable

    #>
    [OutputType([Container])]
    [CmdletBinding( DefaultParameterSetName = 'Name')]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Name', ValueFromPipeline = $true, HelpMessage = 'e.g. IPControl/My Company/etc/etc')]
        [string]$Name,
        [Parameter(Mandatory = $true, ParameterSetName = 'Id', HelpMessage = 'This will be a number')]
        [int64]$Id,
        [Parameter(Mandatory = $true, ParameterSetName = 'Device', ValueFromPipeline = $true)]
        [Device]$Device,
        [Parameter(Mandatory = $false)]
        [switch]$Parent
    )
    Begin {
        If ((Confirm-IPControlSession -Quiet) -ne $true) {
            Write-Warning -Message "Please use Connect-IPControl to establish a new session"
            Break
        }
        [string]$Method = 'GET'
        [hashtable]$parameters = @{}
        $parameters.Add('Method', $Method)
    }
    Process {
        If ($_.container.Length -gt 0) {
            [string]$Name = $_.container
        }
        ElseIf ($_.Length -gt 0) {
            [string]$Name = $_
        }
        [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
        If ($Name.Length -gt 0) {
            [string]$Command = '/Gets/getContainerByName'
            $BodyMetaData.Add('containerName', $Name)
        }
        ElseIf ($Id -gt 0) {
            [string]$Command = '/Gets/getContainerById'
            $BodyMetaData.Add('containerId', $Id)
        }
        Else {
            Write-Warning -Message "Somehow it was not possible to determine the intended command"
            Break
        }
        [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
        If ($null -eq $parameters.Body) {
            $parameters.Add('Body', $Body)
        }
        Else {
            $parameters.Body = $Body
        }
        If ($null -eq $parameters.Command) {
            $parameters.Add('Command', $Command)
        }
        Else {
            $parameters.Command = $Command
        }
        $Error.Clear()
        Try {
            [PSCustomObject]$results = Invoke-IPControlAPI @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Invoke-IPControlAPI failed to execute [$Command] due to [$Message]."
            Break
        }
        $Error.Clear()
        Try {
            [Container]$ipcontrol_container = $results | Select-Object -First 1
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Failed to formulate the response from the API into a [Container] object under Get-IPControlContainer due to [$Message]."
            Break
        }
        If ($Parent -ne $true) {
            Return $ipcontrol_container
        }
        Else {
            [string]$parent_container_name = $ipcontrol_container.parentName
            If ($parent_container_name.Length -eq 0) {
                Write-Warning -Message "Somehow there is no parent container for [$Name]. Is this expected?"
                Break
            }
            [string]$Command = '/Gets/getContainerByName'
            $parameters.Command = $Command
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.Add('containerName', $parent_container_name)
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
            $parameters.Body = $Body
            $Error.Clear()
            Try {
                [PSCustomObject]$results = Invoke-IPControlAPI @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Invoke-IPControlAPI failed to execute [$Command] on the specified Parent Container due to [$Message]."
                Break
            }
            $Error.Clear()
            Try {
                [Container]$ipcontrol_parent_container = $results | Select-Object -First 1
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Failed to formulate the response from the API into a [Container] (parent) object under Get-IPControlContainer due to [$Message]."
                Break
            }
            Return $ipcontrol_parent_container
        }
    }
    End {

    }
}

#EndRegion

#region - Devices

Function Get-IPControlDevice {
    <#

    .SYNOPSIS
    Gets a Device from an IPControl instance

    .DESCRIPTION
    Gets a Device from an IPControl instance

    .PARAMETER IPAddress
    String representing the IP address of the Device to look up (e.g. '1.2.3.4')

    .PARAMETER Container
    Optional string with the name of the Container for the Device. This parameter may only be used with -IPAddress and is only required when the IP address exists in multiple places within the instance (i.e. overlapping address space)

    .PARAMETER Hostname
    String representing the Hostname of the Device to look up (e.g. 'servername.contoso.com')

    .PARAMETER MACAddress
    String representing the MAC address (a.k.a. Hardware address) of the Device to look up. (e.g. 'B8610CAE9619')

    .PARAMETER Id
    Int64 representing the Id of the Device to look up. This will be a number.

    .INPUTS
    IP addresses can be sent across the pipeline.

    .OUTPUTS
    The reponse is provided in a [Device] class object.

    .EXAMPLE
    Gets a single Device by its IP address

    Get-IPControlDevice -IPAddress '1.2.3.4'

    .EXAMPLE
    Gets a single Device by its IP address and its Container name because the IP is in an overlapping network space so the Container name is required to distinguish it.

    Get-IPControlDevice -IPAddress '1.2.3.4' -Container 'IPControl/My Company/etc/etc'

    .EXAMPLE
    Gets a single Device by its hardware address (a.k.a. MAC address)

    Get-IPControlDevice -MACAddress 'B8610CAE9619'

    .EXAMPLE
    Gets a single Device by its hostname

    Get-IPControlDevice -Hostname 'Printer_10-226-124-10'

    .EXAMPLE
    Gets a single Device by its IPControl Id

    Get-IPControlDevice -Id 123456

    .EXAMPLE
    Uses the pipeline to get a series of Devices by their IP addresses

    '1.2.3.4', '2.3.4.5' | Get-IPControlDevice

    .NOTES
    An "IP Address" in IPControl is known as a "Device".

    You must use Connect-IPControl to establish a connection and define the global session variable

    If the Container name is specified and it doesn't exist then the lookup will fail with 400 Bad Request.

    #>
    [OutputType([Container])]
    [CmdletBinding( DefaultParameterSetName = 'IPAddress' )]
    Param(
        [ValidateScript({ $_ -match '^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$' })]
        [Parameter(Mandatory = $true, ParameterSetName = 'IPAddress', ValueFromPipeline = $true, HelpMessage = 'e.g. 1.2.3.4')]
        [string]$IPAddress,
        [Parameter(Mandatory = $false, ParameterSetName = 'IPAddress', ValueFromPipeline = $true, HelpMessage = 'e.g. IPControl/My Company/etc/etc')]
        [string]$Container,
        [Parameter(Mandatory = $true, ParameterSetName = 'Hostname', HelpMessage = 'e.g. server.contoso.com')]
        [string]$Hostname,
        [ValidateScript({ $_ -cmatch '^[A-F0-9]{12}$' })]
        [Parameter(Mandatory = $true, ParameterSetName = 'HWAddress', HelpMessage = 'e.g. B8610CAE9619')]
        [string]$MACAddress,
        [Parameter(Mandatory = $true, ParameterSetName = 'Id', HelpMessage = 'This will be a number')]
        [int64]$Id
    )
    Begin {
        If ((Confirm-IPControlSession -Quiet) -ne $true) {
            Write-Warning -Message "Please use Connect-IPControl to establish a new session"
            Break
        }
        [string]$Method = 'GET'
        [hashtable]$parameters = @{}
        $parameters.Add('Method', $Method)
    }
    Process {
        If ($_ -match '^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$') {
            [string]$IPAddress = $_
        }
        [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
        If ($IPAddress.Length -gt 0) {
            [string]$Command = '/Gets/getDeviceByIPAddr'
            $BodyMetaData.Add('ipAddress', $IPAddress)
            If ($Container.Length -gt 0) {
                $BodyMetaData.Add('container', $Container)
            }
        }
        ElseIf ($Hostname.Length -gt 0) {
            [string]$Command = '/Gets/getDeviceByHostname'
            $BodyMetaData.Add('hostname', $Hostname)
        }
        ElseIf ($MACAddress.Length -gt 0) {
            [string]$Command = '/Gets/getDeviceByMACAddress'
            $BodyMetaData.Add('macAddress', $MACAddress)
        }
        ElseIf ($Id -gt 0) {
            [string]$Command = '/Gets/getDeviceById'
            $BodyMetaData.Add('id', $Id)
        }
        Else {
            Write-Warning -Message "Somehow it was not possible to determine the intended command"
            Break
        }
        [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
        If ($null -eq $parameters.Body) {
            $parameters.Add('Body', $Body)
        }
        Else {
            $parameters.Body = $Body
        }
        If ($null -eq $parameters.Command) {
            $parameters.Add('Command', $Command)
        }
        Else {
            $parameters.Command = $Command
        }
        $Error.Clear()
        Try {
            [PSCustomObject]$results = Invoke-IPControlAPI @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Invoke-IPControlAPI failed to execute [$Command] due to [$Message]."
            Break
        }
        $Error.Clear()
        Try {
            [Device]$ipcontrol_device = $results | Select-Object -First 1
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Failed to formulate the response from the API into a [Device] object under Get-IPControlDevice due to [$Message]."
            Break
        }
        Return $ipcontrol_device
    }
    End {

    }
}

Function Remove-IPControlDevice {
    <#

    .SYNOPSIS
    Remove a Device (and its records) from an IPControl instance

    .DESCRIPTION
    Remove a Device (and its records) from an IPControl instance

    .PARAMETER Device
    [Device] object representing the Device to get deleted. Use Get-IPControlDevice to retrieve these.

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false

    .PARAMETER Quiet
    Suppress the output informational message when the delete operation is successful.

    .INPUTS
    Device objects from Get-IPControlDevice can be sent across the pipeline.

    .OUTPUTS
    An informational message will be written to the host if the delete operation is successful.

    .EXAMPLE
    Forcibly and quietly removes a Device with the IP address of '1.2.3.4' while using the pipeline.

    Get-IPControlDevice -IPAddress '1.2.3.4' | Remove-IPControlDevice -Force -Quiet

    .EXAMPLE
    Removes a Device with the IP address of '1.2.3.4' without using the pipeline.

    Remove-IPControlDevice -Device (Get-IPControlDevice -IPAddress '1.2.3.4')

    .NOTES
    You must use Connect-IPControl to establish a connection and define the global session variable

    The Container name is always included in the request

    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Device]$Device,
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    Begin {
        If ((Confirm-IPControlSession -Quiet) -ne $true) {
            Write-Warning -Message "Please use Connect-IPControl to establish a new session"
            Break
        }
        [string]$Method = 'DELETE'
        [string]$Command = '/Deletes/deleteDevice'
        [hashtable]$parameters = @{}
        $parameters.Add('Method', $Method)
        $parameters.Add('Command', $Command)
        $parameters.Add('ContentType', 'application/json')
    }
    Process {
        If ($_ -is [Device]) {
            [Device]$Device = $_
        }
        [string]$device_ip_address = $Device.ipAddress
        [string]$device_container = $Device.container
        If ($device_ip_address.Length -eq 0) {
            Write-Warning -Message "Somehow the IP address of the Device is empty"
            Break
        }
        ElseIf ($device_container.Length -eq 0) {
            Write-Warning -Message "Somehow the Container of the Device is empty"
            Break
        }
        [hashtable]$inpDev = @{}
        $inpDev.Add('ipAddress', $device_ip_address )
        $inpDev.Add('container', $device_container )
        [string]$Body = @{'inpDev' = $inpDev } | ConvertTo-Json -Compress
        If ($null -eq $parameters.Body) {
            $parameters.Add('Body', $Body)
        }
        Else {
            $parameters.Body = $Body
        }
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($device_ip_address)")) -eq $true) {
            $Error.Clear()
            Try {
                [string]$results = Invoke-IPControlAPI @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Invoke-IPControlAPI failed to execute [$Command] due to [$Message]."
                Break
            }
            If ($results.Length -gt 0) {
                If ($Quiet -ne $true) {
                    Return $results
                }
            }
            Else {
                Write-Warning -Message "The response from [$Command] was empty. Something might be wrong..."
            }
        }
    }
    End {

    }
}

#endregion

#region - Device Resource Records

Function Get-IPControlDeviceResourceRecord {
    <#

    .SYNOPSIS
    Gets the Resource Records from a Device on an IPControl instance

    .DESCRIPTION
    Gets the Resource Records from a Device on an IPControl instance

    .PARAMETER Device
    Mandatory [Device] object representing the Device whose resource records are to be retrieved. Use Get-IPControlDevice to obtain this.

    .INPUTS
    Device objects from Get-IPControlDevice

    .OUTPUTS
    Resource Record objects

    .EXAMPLE
    Gets the Resource Records from a Device with an IP address of '1.2.3.4'

    Get-IPControlDeviceResourceRecord -Device (Get-IPControlDevice -IPAddress '1.2.3.4')

    .NOTES

    You must use Connect-IPControl to establish a connection and define the global session variable

    #>
    [OutputType([ResourceRecord[]])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [Device]$Device
    )
    If ((Confirm-IPControlSession -Quiet) -ne $true) {
        Write-Warning -Message "Please use Connect-IPControl to establish a new session"
        Break
    }
    [string]$device_ip_address = $Device.ipAddress
    If ($device_ip_address -notmatch '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}') {
        Write-Warning -Message "Somehow the IP address couldn't be extracted from the `$Device variable"
        Break
    }

    # Part 1 - Initialize the export
    $Error.Clear()
    Try {
        [initExportDevice]$initExportDevice = Initialize-IPControlDeviceResourceRecordExport -Device $Device
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Initialize-IPControlDeviceResourceRecordExport failed to execute against [$device_ip_address] due to [$Message]."
        Break
    }
    [string]$contextId = $initExportDevice.contextId
    If ($contextId.Length -eq 0) {
        Write-Warning -Message "Somehow the Context Id couldn't be extracted from the `$Device variable"
        Break
    }
    Write-Verbose -Message "Received back $contextId to start exporting resource records from $device_ip_address"

    # Part 2 - Retrieve the export
    [string]$Method = 'POST'
    [string]$Command = '/Exports/exportDeviceResourceRec'
    [hashtable]$parameters = @{}
    $parameters.Add('Method', $Method)
    $parameters.Add('Command', $Command)
    $parameters.Add('ContentType', 'application/json')
    [hashtable]$context = @{}
    [int64]$firstResultPos = $initExportDevice.firstResultPos
    [int64]$internalResultCount = $initExportDevice.internalResultCount
    [int64]$maxResults = $initExportDevice.maxResults
    [string]$query = $initExportDevice.query
    [int64]$resultCount = $initExportDevice.resultCount
    $context.Add('contextId', $contextId)
    $context.Add('contextType', 'Export_Device')
    $context.Add('filter', "IPAddress=$device_ip_address")
    $context.Add('firstResultPos', $firstResultPos)
    $context.Add('internalResultCount', $internalResultCount)
    $context.Add('maxResults', $maxResults)
    $context.Add('query', $query)
    $context.Add('resultCount', $resultCount)
    $context.Add('options', @($null))
    [string]$Body = @{'context' = $context; } | ConvertTo-Json -Compress
    $parameters.Add('Body', $Body)
    $Error.Clear()
    Try {
        [PSCustomObject]$results = Invoke-IPControlAPI @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Invoke-IPControlAPI failed to execute [$Command] due to [$Message]."
        Break
    }
    # Part 3 - Close the export session
    $Error.Clear()
    Try {
        Complete-IPControlDeviceResourceRecordExport -initExportDevice $initExportDevice
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Complete-IPControlDeviceResourceRecordExport failed to execute against $contextId ($device_ip_address) due to [$Message]."
        Break
    }
    $Error.Clear()
    Try {
        [ResourceRecord[]]$ipcontrol_records = $results
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Failed to formulate the response from the API into [ResourceRecord] objects under Export-IPControlDeviceResourceRecord due to [$Message]."
        Break
    }
    If ($ipcontrol_records.Count -gt 0) {
        Return $ipcontrol_records
    }
}

Function Initialize-IPControlDeviceResourceRecordExport {
    <#

    .SYNOPSIS
    Initializes (begins) the process to Export Device Resource Records on an IPControl instance

    .DESCRIPTION
    Initializes (begins) the process to Export Device Resource Records on an IPControl instance

    .PARAMETER Device
    Mandatory [Device] object representing the Device whose resource records are to be exported. Use Get-IPControlDevice to retrieve these.

    .INPUTS
    Device objects from Get-IPControlDevice

    .OUTPUTS
    A [initExportDevice] object will be returned for use with exporting.

    .EXAMPLE
    Initialize-IPControlDeviceResourceRecordExport -Device $Device

    .NOTES
    Exports cannot occur without first initializing.

    This function is not intended to be used standalone, rather it is part of the Get-IPControlResourceRecord function set.

    #>
    [OutputType([initExportDevice])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [Device]$Device,
        [Parameter(Mandatory = $false)]
        [int32]$pageSize = 0,
        [Parameter(Mandatory = $false)]
        [int32]$firstResultPos = 0
    )
    If ((Confirm-IPControlSession -Quiet) -ne $true) {
        Write-Warning -Message "Please use Connect-IPControl to establish a new session"
        Break
    }
    [string]$Method = 'POST'
    [string]$Command = '/Exports/initExportDeviceResourceRec'
    [hashtable]$parameters = @{}
    $parameters.Add('Method', $Method)
    $parameters.Add('Command', $Command)
    $parameters.Add('ContentType', 'application/json')
    [string]$device_ip_address = $Device.ipAddress
    [string]$device_container = $Device.container
    If ($device_ip_address.Length -eq 0) {
        Write-Warning -Message "Somehow the IP address of the Device is empty"
        Break
    }
    ElseIf ($device_container.Length -eq 0) {
        Write-Warning -Message "Somehow the Container of the Device is empty"
        Break
    }
    [string]$Body = @{filter = "IPAddress=$device_ip_address"; pageSize = $pageSize; firstResultPos = $firstResultPos; } | ConvertTo-Json -Compress
    #[string]$Body = @{filter = "IPAddress=$device_ip_address"; } | ConvertTo-Json -Compress
    $parameters.Add('Body', $Body)
    $Error.Clear()
    Try {
        [PSCustomObject]$results = Invoke-IPControlAPI @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Invoke-IPControlAPI failed to execute [$Command] due to [$Message]."
        Break
    }
    $Error.Clear()
    Try {
        [initExportDevice]$ipcontrol_init_export_device = $results | Select-Object -First 1
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Failed to formulate the response from the API into an [initExportDevice] object under Initialize-IPControlDeviceResourceRecordExport due to [$Message]."
        Break
    }
    Return $ipcontrol_init_export_device
    End {

    }
}

Function Complete-IPControlDeviceResourceRecordExport {
    <#

    .SYNOPSIS
    Completes (finishes) the process to Export Device Resource Records on an IPControl instance

    .DESCRIPTION
    Completes (finishes) the process to Export Device Resource Records on an IPControl instance

    .PARAMETER initExportDevice
    Mandatory [initExportDevice] object representing the Device Export to be completed. Initialize-IPControlDeviceResourceRecordExport to create these.

    .INPUTS
    Device objects from Get-IPControlDevice

    .OUTPUTS
    None

    .EXAMPLE
    Initializes and then immediately closes a device resource record export request (for demonstration purposes)

    $initExportDevice = Initialize-IPControlDeviceResourceRecordExport -Device (Get-IPControlDevice -IPAddress '1.2.3.4')
    Complete-IPControlDeviceResourceRecordExport -initExportDevice $initExportDevice

    .NOTES
    Export sessions that were started with Initialize-IPControlDeviceResourceRecordExport must subsequently be completed (closed) with Complete-IPControlDeviceResourceRecordExport

    This function is not intended to be used standalone, rather it is part of the ? function set.

    You must use Connect-IPControl to establish a connection and define the global session variable

    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [initExportDevice]$initExportDevice
    )
    If ((Confirm-IPControlSession -Quiet) -ne $true) {
        Write-Warning -Message "Please use Connect-IPControl to establish a new session"
        Break
    }
    [string]$Method = 'POST'
    [string]$Command = '/Exports/endExportDeviceResourceRec'
    [hashtable]$parameters = @{}
    $parameters.Add('Method', $Method)
    $parameters.Add('Command', $Command)
    $parameters.Add('ContentType', 'application/json')
    [hashtable]$context = @{}
    [string]$device_ip_address = $initExportDevice.filter -replace 'IPAddress='
    If ($device_ip_address -notmatch '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}') {
        Write-Warning -Message "Somehow the IP address couldn't be extracted from the `$initExportDevice variable"
        Break
    }
    [string]$contextId = $initExportDevice.contextId
    If ($contextId.Length -eq 0) {
        Write-Warning -Message "Somehow the Context Id couldn't be extracted from the `$initExportDevice variable"
        Break
    }
    [int64]$firstResultPos = $initExportDevice.firstResultPos
    [int64]$internalResultCount = $initExportDevice.internalResultCount
    [int64]$maxResults = $initExportDevice.maxResults
    [string]$query = $initExportDevice.query
    [int64]$resultCount = $initExportDevice.resultCount
    $context.Add('contextId', $contextId)
    $context.Add('contextType', 'Export_Device')
    $context.Add('filter', "IPAddress=$device_ip_address")
    $context.Add('firstResultPos', $firstResultPos)
    $context.Add('internalResultCount', $internalResultCount)
    $context.Add('maxResults', $maxResults)
    $context.Add('query', $query)
    $context.Add('resultCount', $resultCount)
    $context.Add('options', @($null))
    [string]$Body = @{'context' = $context; } | ConvertTo-Json -Compress
    $parameters.Add('Body', $Body)
    $Error.Clear()
    Try {
        [PSCustomObject]$results = Invoke-IPControlAPI @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Invoke-IPControlAPI failed to execute [$Command] due to [$Message]."
        Break
    }
    If ($results.Content -eq 'null') {
        Write-Verbose -Message "The $contextId session was cleaned up"
    }
}

#endregion

#EndRegion

#Region = Utility Functions =

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
    Invoke-IPControlAPI -Command '/Gets/getDeviceByIPAddr' -Method GET -Body 'ipAddress=1.2.3.4'

    .NOTES
    You must use Connect-IPControl to establish a connection and define the global session variable

    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Command,
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'DELETE')]
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
        $parameters.Add('Headers', $ipcontrol_session.Header)
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
        If (($return_code -eq 400) -and ($Command -match '\/[a-z]{1,}\/initExport[a-z]{1,}')) {
            Write-Warning -Message 'If an initExport command is failing with 400 then the most likely reason is because you didn''t clean up your session. Please, clean up your session after initiating any exports.'
            Break
        }
        ElseIf ($return_code -gt 0) {
            [string]$ReturnCodeWarning = Switch ($return_code) {
                400 { "You received HTTP Code $return_code (Bad Request). Most likely, the object you specified doesn't exist" }
                401 { "You received HTTP Code $return_code (Unauthorized). HAS YOUR TOKEN EXPIRED? :-)" }
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



