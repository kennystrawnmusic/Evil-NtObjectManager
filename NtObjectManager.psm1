#  Copyright 2016, 2017 Google Inc. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

Set-StrictMode -Version Latest

Import-Module "$PSScriptRoot\NtObjectManager.dll"


<#
.SYNOPSIS
Get an appcontainer profile for a specified package name.
.DESCRIPTION
This cmdlet gets an appcontainer profile for a specified package name.
.PARAMETER Name
Specify appcontainer name to use for the profile.
.PARAMETER OpenAlways
Specify to open the profile even if it doesn't exist.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.AppModel.AppContainerProfile
.EXAMPLE
Get-AppContainerProfile
Get appcontainer profiles for all installed packages.
.EXAMPLE
Get-AppContainerProfile -Name Package_aslkjdskjds
Get an appcontainer profile from a package name.
#>
function Get-AppContainerProfile {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(ParameterSetName = "All")]
        [switch]$AllUsers,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromName")]
        [string]$Name,
        [parameter(ParameterSetName = "FromName")]
        [switch]$OpenAlways
    )

    switch ($PSCmdlet.ParameterSetName) {
        "All" {
            [NtCoreLib.Win32.AppModel.AppContainerProfile]::GetAppContainerProfiles() | Write-Output
        }
        "FromName" {
            if ($OpenAlways) {
                $prof = [NtCoreLib.Win32.AppModel.AppContainerProfile]::OpenExisting($Name, $false)
                if (!$prof.IsSuccess) {
                    $prof = [NtCoreLib.Win32.AppModel.AppContainerProfile]::Open($Name)
                }
                $prof | Write-Output
            } else {
                [NtCoreLib.Win32.AppModel.AppContainerProfile]::OpenExisting($Name) | Write-Output
            }
        }
    }
}

<#
.SYNOPSIS
Create a new appcontainer profile for a specified package name.
.DESCRIPTION
This cmdlet create a new appcontainer profile for a specified package name. If the profile already exists it'll open it.
.PARAMETER Name
Specify appcontainer name to use for the profile.
.PARAMETER DisplayName
Specify the profile display name.
.PARAMETER Description
Specify the profile description.
.PARAMETER DeleteOnClose
Specify the profile should be deleted when closed.
.PARAMETER TemporaryProfile
Specify to create a temporary profile. Close the profile after use to delete it.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.AppModel.AppContainerProfile
.EXAMPLE
New-AppContainerProfile -Name Package_aslkjdskjds
Create a new AppContainer profile with a specified name.
.EXAMPLE
Get-AppContainerProfile -TemporaryProfile
Create a new temporary profile.
#>
function New-AppContainerProfile {
    [CmdletBinding(DefaultParameterSetName = "FromName")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromName")]
        [string]$Name,
        [parameter(Position = 1, ParameterSetName = "FromName")]
        [string]$DisplayName = "DisplayName",
        [parameter(Position = 2, ParameterSetName = "FromName")]
        [string]$Description = "Description",
        [parameter(ParameterSetName = "FromName")]
        [parameter(ParameterSetName = "FromTemp")]
        [NtCoreLib.Security.Authorization.Sid[]]$Capabilities,
        [parameter(ParameterSetName = "FromName")]
        [switch]$DeleteOnClose,
        [parameter(Mandatory, ParameterSetName = "FromTemp")]
        [switch]$TemporaryProfile
    )

    switch ($PSCmdlet.ParameterSetName) {
        "FromName" {
            $prof = [NtCoreLib.Win32.AppModel.AppContainerProfile]::Create($Name, $DisplayName, $Description, $Capabilities)
            if ($null -ne $prof) {
                $prof.DeleteOnClose = $DeleteOnClose
                Write-Output $prof
            }
        }
        "FromTemp" {
            [NtCoreLib.Win32.AppModel.AppContainerProfile]::CreateTemporary($Capabilities) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Delete an appcontainer profile.
.DESCRIPTION
This cmdlet deletes an appcontainer profile for a specified package name or from its profile.
.PARAMETER Name
Specify appcontainer name to delete.
.PARAMETER Profile
Specify appcontainer profile to delete.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Remove-AppContainerProfile -Name "profile_to_remove"
Delete an appcontainer profiles by name.
.EXAMPLE
Remove-AppContainerProfile -Profile $prof
Delete an appcontainer profiles from an existing profile.
#>
function Remove-AppContainerProfile {
    [CmdletBinding(DefaultParameterSetName = "FromName")]
    param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromProfile")]
        [NtCoreLib.Win32.AppModel.AppContainerProfile]$Profile,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromName")]
        [string]$Name
    )

    switch ($PSCmdlet.ParameterSetName) {
        "FromProfile" {
            $Profile.Delete()
        }
        "FromName" {
            [NtCoreLib.Win32.AppModel.AppContainerProfile]::Delete($Name)
        }
    }
}

<#
.SYNOPSIS
Start an application model application.
.DESCRIPTION
This cmdlet starts an application model application from it's application model ID.
.PARAMETER AppModelId
Specify the application model ID.
.PARAMETER Argument
Specify the argument for the application.
.PARAMETER PassThru
Specify to pass through a process object for the application.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtProcess
.EXAMPLE
Start-AppModelApplication -AppModelId "Microsoft.WindowsCalculator_8wekyb3d8bbwe!App"
Start the Windows calculator.
#>
function Start-AppModelApplication {
    param(
        [parameter(Mandatory, Position = 0)]
        [string]$AppModelId,
        [parameter(Position = 1)]
        [string]$Argument = "",
        [switch]$PassThru
    )
    try {
        $app_id = [NtCoreLib.Win32.AppModel.AppModelUtils]::ActivateApplication($AppModelId, $Argument)
        if ($PassThru) {
            Get-NtProcess -ProcessId $app_id
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Query an app model policy for the a process.
.DESCRIPTION
This cmdlet queries the app model policy for a process.
.PARAMETER Process
Specify the process to get the app model policy for.
.PARAMETER Policy
Specify a specific policy to query.
.INPUTS
None
.OUTPUTS
NtCoreLib.AppModelPolicy_PolicyValue
.EXAMPLE
Get-AppModelApplicationPolicy -Process $proc
Query all app model policies.
#>
function Get-AppModelApplicationPolicy {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtProcess]$Process,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromPolicy")]
        [NtCoreLib.AppModelPolicy_Type[]]$Policy
    )

    try {
        Use-NtObject($token = Get-NtToken -Process $proc) {
            switch($PSCmdlet.ParameterSetName) {
                "All" {
                    $token.AppModelPolicyDictionary | Write-Output
                }
                "FromPolicy" {
                    foreach($pol in $Policy) {
                        $token.GetAppModelPolicy($pol) | Write-Output
                    }
                }
            }
        }
    } catch {
        Write-Error $_
    }
}

function Check-FullTrust {
    param([xml]$Manifest)
    if ($Manifest -eq $null) {
        return $false
    }
    $nsmgr = [System.Xml.XmlNamespaceManager]::new($Manifest.NameTable)
    $nsmgr.AddNamespace("rescap", "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities")
    $Manifest.SelectSingleNode("//rescap:Capability[@Name='runFullTrust']", $nsmgr) -ne $null
}

function Get-AppExtensions {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [xml]$Manifest
    )
    PROCESS {
        if ($Manifest -eq $null) {
            return
        }
        $nsmgr = [System.Xml.XmlNamespaceManager]::new($Manifest.NameTable)
        $nsmgr.AddNamespace("desktop", "http://schemas.microsoft.com/appx/manifest/desktop/windows10")
        $nodes = $Manifest.SelectNodes("//desktop:Extension[@Category='windows.fullTrustProcess']", $nsmgr)
        foreach($node in $nodes) {
            Write-Output $node.GetAttribute("Executable")
        }
    }
}

function Get-FullTrustApplications {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [xml]$Manifest,
        [parameter(Mandatory)]
        [string]$PackageFamilyName
    )
    PROCESS {
        if ($Manifest -eq $null) {
            return
        }
        $nsmgr = [System.Xml.XmlNamespaceManager]::new($Manifest.NameTable)
        $nsmgr.AddNamespace("app", "http://schemas.microsoft.com/appx/manifest/foundation/windows10")
        $nodes = $Manifest.SelectNodes("//app:Application[@EntryPoint='Windows.FullTrustApplication']", $nsmgr)
        foreach($node in $nodes) {
            $id = $node.GetAttribute("Id")
            $props = @{
                ApplicationUserModelId="$PackageFamilyName!$id";
                Executable=$node.GetAttribute("Executable");
            }

            Write-Output $(New-Object psobject -Property $props)
        }
    }
}

function Read-DesktopAppxManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $Package,
        [switch]$AllUsers
    )
    PROCESS {
        $Manifest = Get-AppxPackageManifest $Package
        if (-not $(Check-FullTrust $Manifest)) {
            return
        }
        $install_location = $Package.InstallLocation
        $profile_dir = ""
        if (-not $AllUsers) {
            $profile_dir = "$env:LOCALAPPDATA\Packages\$($Package.PackageFamilyName)"
        }

        $has_registry = (Test-Path "$install_location\registry.dat") -or `
            (Test-Path "$install_location\user.dat") -or `
            (Test-Path "$install_location\userclasses.dat")

        $vfs_files = @{}
        $vfs_root = "$install_location\VFS"
        if (Test-Path $vfs_root) {
            foreach($f in (Get-ChildItem $vfs_root)) {
                $name = $f.Name
                $vfs_files[$name] = Get-ChildItem -Recurse "$vfs_root\$name"
            }
        }

        $props = @{
            Name=$Package.Name;
            Architecture=$Package.Architecture;
            Version=$Package.Version;
            Publisher=$Package.Publisher;
            PackageFamilyName=$Package.PackageFamilyName;
            InstallLocation=$install_location;
            Manifest=Get-AppxPackageManifest $Package;
            Applications=Get-FullTrustApplications $Manifest $Package.PackageFamilyName;
            Extensions=Get-AppExtensions $Manifest;
            VFSFiles=$vfs_files;
            HasRegistry=$has_registry;
            ProfileDir=$profile_dir;
        }

        New-Object psobject -Property $props
    }
}

<#
.SYNOPSIS
Get a list AppX packages with Desktop Bridge components.
.DESCRIPTION
This cmdlet gets a list of installed AppX packages which are either directly full trust applications or 
have an extension which can be used to run full trust applications.
.PARAMETER AllUsers
Specify getting information for all users, needs admin privileges.
.INPUTS
None
.OUTPUTS
Package results.
.EXAMPLE
Get-AppxDesktopBridge
Get all desktop bridge AppX packages for current user.
.EXAMPLE
Get-AppxDesktopBridge -AllUsers
Get all desktop bridge AppX packages for all users.
#>
function Get-AppxDesktopBridge {
    param([switch]$AllUsers)
    Get-AppxPackage -AllUsers:$AllUsers -PackageTypeFilter Main | Read-DesktopAppxManifest -AllUsers:$AllUsers
}

<#
.SYNOPSIS
Get list of package SIDs granted loopback exceptions.
.DESCRIPTION
This cmdlet gets the list of package SIDs which have been granted loopback exceptions.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.Sid[]
.EXAMPLE
Get-AppModelLoopbackException
Get the list of loopback exception package SIDs.
#>
function Get-AppModelLoopbackException {
    [NtCoreLib.Win32.AppModel.AppModelUtils]::GetLoopbackException()
}

<#
.SYNOPSIS
Add a package SID to the list of granted loopback exceptions.
.DESCRIPTION
This cmdlet adds a package SID to the list of granted loopback exceptions.
.PARAMETER PackageSid
The package SID to add. Can be an SDDL SID or a name.
.INPUTS
string[]
.OUTPUTS
None
.EXAMPLE
Add-AppModelLoopbackException -PackageSid $package_sid
Add $package_sid to the list of loopback exceptions.
.EXAMPLE
Add-AppModelLoopbackException -PackageSid "ABC"
Add package "ABC" to the list of loopback exceptions.
#>
function Add-AppModelLoopbackException {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [string]$PackageSid
    )
    PROCESS {
        try {
            $sid = [NtCoreLib.Win32.Security.Win32Security]::GetPackageSidFromName($PackageSid)
            [NtCoreLib.Win32.AppModel.AppModelUtils]::AddLoopbackException($sid)
        } catch {
            Write-Error $_
        }
    }
}

<#
.SYNOPSIS
Remove a package SID from the list of granted loopback exceptions.
.DESCRIPTION
This cmdlet removes a package SID from the list of granted loopback exceptions.
.PARAMETER PackageSid
The package SID to remove.
.INPUTS
string[]
.OUTPUTS
None
.EXAMPLE
Remove-AppModelLoopbackException -PackageSid $package_sid
Remove $package_sid from the list of loopback exceptions.
.EXAMPLE
Remove-AppModelLoopbackException -PackageSid "ABC"
Remove package "ABC" from the list of loopback exceptions.
#>
function Remove-AppModelLoopbackException {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [string]$PackageSid
    )
    PROCESS {
        try {
            $sid = [NtCoreLib.Win32.Security.Win32Security]::GetPackageSidFromName($PackageSid)
            [NtCoreLib.Win32.AppModel.AppModelUtils]::RemoveLoopbackException($sid)
        } catch {
            Write-Error $_
        }
    }
}

<#
.SYNOPSIS
Gets the execution alias information from a name.
.DESCRIPTION
This cmdlet looks up an execution alias and tries to parse its reparse point to extract internal information.
.PARAMETER AliasName
The alias name to lookup. Can be either a full path to the alias or a name which will be found in the WindowsApps
folder.
.EXAMPLE
Get-ExecutionAlias ubuntu.exe
Get the ubuntu.exe execution alias from local appdata.
.EXAMPLE
Get-ExecutionAlias c:\path\to\alias.exe
Get the alias.exe execution alias from an absolute path.
#>
function Get-ExecutionAlias {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$AliasName
    )

    if (Test-Path $AliasName) {
        $path = Resolve-Path $AliasName
    }
    else {
        $path = $env:LOCALAPPDATA + "\Microsoft\WindowsApps\$AliasName"
    }

    Use-NtObject($file = Get-NtFile -Path $path -Win32Path -Options OpenReparsePoint, SynchronousIoNonAlert `
            -Access GenericRead, Synchronize) {
        $file.GetReparsePoint()
    }
}

<#
.SYNOPSIS
Creates a new execution alias information or updates and existing one.
.DESCRIPTION
This cmdlet creates a new execution alias for a packaged application.
.PARAMETER PackageName
The name of the UWP package.
.PARAMETER EntryPoint
The entry point of the application
.PARAMETER Target
The target executable path
.PARAMETER AppType
The application type.
.PARAMETER Version
Version number
.EXAMPLE
Set-ExecutionAlias c:\path\to\alias.exe -PackageName test -EntryPoint test!test -Target c:\test.exe -Flags 48 -Version 3
Set the alias.exe execution alias.
#>
function Set-ExecutionAlias {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Path,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$PackageName,
        [Parameter(Mandatory = $true, Position = 2)]
        [string]$EntryPoint,
        [Parameter(Mandatory = $true, Position = 3)]
        [string]$Target,
        [NtCoreLib.Kernel.IO.ExecutionAliasAppType]$AppType = "Desktop",
        [Int32]$Version = 3
    )

    $rp = [NtCoreLib.Kernel.IO.ExecutionAliasReparseBuffer]::new($Version, $PackageName, $EntryPoint, $Target, $AppType)
    Use-NtObject($file = New-NtFile -Path $Path -Win32Path -Options OpenReparsePoint, SynchronousIoNonAlert `
            -Access GenericWrite, Synchronize -Disposition OpenIf) {
        $file.SetReparsePoint($rp)
    }
}

$layer_completer = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    [NtCoreLib.Net.Firewall.FirewallUtils]::GetKnownLayerNames() | Where-Object { $_ -like "$wordToComplete*" }
}

$sublayer_completer = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    [NtCoreLib.Net.Firewall.FirewallUtils]::GetKnownSubLayerNames() | Where-Object { $_ -like "$wordToComplete*" }
}

$callout_completer = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    [NtCoreLib.Net.Firewall.FirewallUtils]::GetKnownCalloutNames() | Where-Object { $_ -like "$wordToComplete*" }
}

$Script:GlobalFwEngine = $null

function Get-FwEngineSingleton {
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine
    )

    if ($null -ne $Engine) {
        return $Engine
    }

    if ($Script:GlobalFwEngine -eq $null) {
        $Script:GlobalFwEngine = Get-FwEngine
    }
    return $Script:GlobalFwEngine
}

<#
.SYNOPSIS
Get a firewall engine instance.
.DESCRIPTION
This cmdlet gets an instance of the firewall engine.
.PARAMETER ServerName
The name of the server running the firewall service.
.PARAMETER Credentials
The user credentials for the RPC connection.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallEngine
.EXAMPLE
Get-FwEngine
Get local firewall engine.
.EXAMPLE
Get-FwEngine -ServerName "SERVER1"
Get firewall engine on server "SERVER1"
#>
function Get-FwEngine {
    [CmdletBinding()]
    Param(
        [string]$ServerName,
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationType]$AuthnService = "WinNT",
        [NtCoreLib.Win32.Security.Authentication.UserCredentials]$Credentials,
        [switch]$Dynamic
    )

    $session = if ($Dynamic) {
        [NtCoreLib.Net.Firewall.FirewallSession]::new("Dynamic")
    }

    [NtCoreLib.Net.Firewall.FirewallEngine]::Open($ServerName, $AuthnService, $Credentials, $session)
}

<#
.SYNOPSIS
Get a firewall layer.
.DESCRIPTION
This cmdlet gets a firewall layer from an engine. It can return a specific layer or all layers.
.PARAMETER Engine
The firewall engine to query. Optional, if not specified will use a globally set engine.
.PARAMETER Key
Specify the layer key.
.PARAMETER Name
Specify the well-known name of the layer.
.PARAMETER AleLayer
Specify the ALE layer type.
.PARAMETER Id
Specify the ID of the layer.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallLayer[]
.EXAMPLE
Get-FwLayer -Engine $engine
Get all firewall layers.
.EXAMPLE
Get-FwLayer -Engine $engine -Key "c38d57d1-05a7-4c33-904f-7fbceee60e82"
Get firewall layer from key.
.EXAMPLE
Get-FwLayer -Engine $engine -Key "FWPM_LAYER_ALE_AUTH_CONNECT_V4"
Get firewall layer from name.
.EXAMPLE
Get-FwLayer -Engine $engine -Id 1234
Get firewall layer from its ID.
#>
function Get-FwLayer {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromKey")]
        [NtObjectManager.Utils.Firewall.FirewallLayerGuid]$Key,
        [parameter(Mandatory, ParameterSetName="FromAleLayer")]
        [NtCoreLib.Net.Firewall.FirewallAleLayer]$AleLayer,
        [parameter(Mandatory, ParameterSetName="FromId")]
        [int]$Id
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine

        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Engine.EnumerateLayers() | Write-Output
            }
            "FromKey" {
                $Engine.GetLayer($Key.Id)
            }
            "FromAleLayer" {
                $Engine.GetLayer($AleLayer)
            }
            "FromId" {
                $Engine.GetLayer($Id)
            }
        }
    } catch {
        Write-Error $_
    }
}

Register-ArgumentCompleter -CommandName Get-FwLayer -ParameterName Key -ScriptBlock $layer_completer

<#
.SYNOPSIS
Get a firewall sub-layer.
.DESCRIPTION
This cmdlet gets a firewall sub-layer from an engine. It can return a specific sub-layer or all sub-layers.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER Key
Specify the sub-layer key.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallSubLayer[]
.EXAMPLE
Get-FwSubLayer
Get all firewall sub-layers.
.EXAMPLE
Get-FwSubLayer -Key "eebecc03-ced4-4380-819a-2734397b2b74"
Get firewall sub-layer from key.
.EXAMPLE
Get-FwSubLayer -Key "FWPM_SUBLAYER_UNIVERSAL"
Get firewall sub-layer from name.
#>
function Get-FwSubLayer {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, ParameterSetName="FromKey")]
        [NtObjectManager.Utils.Firewall.FirewallSubLayerGuid]$Key
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine

        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Engine.EnumerateSubLayers() | Write-Output
            }
            "FromKey" {
                $Engine.GetSubLayer($Key.Id)
            }
        }
    } catch {
        Write-Error $_
    }
}

Register-ArgumentCompleter -CommandName Get-FwSubLayer -ParameterName Key -ScriptBlock $sublayer_completer

<#
.SYNOPSIS
Get firewall filters.
.DESCRIPTION
This cmdlet gets firewall filters layer from an engine. It can return a filter in a specific layer or for all layers.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER LayerKey
Specify the layer key.
.PARAMETER AleLayer
Specify the ALE layer type.
.PARAMETER Layer
Specify a layer object to query the filters from.
.PARAMETER Key
Specify the filter's key.
.PARAMETER Id
Specify the filter's ID.
.PARAMETER Template
Specify the filter template to enumerate.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallLayer[]
.EXAMPLE
Get-FwFilter -Engine $engine
Get all firewall filters.
.EXAMPLE
Get-FwFilter -Engine $engine -LayerKey "c38d57d1-05a7-4c33-904f-7fbceee60e82"
Get firewall filters from layer key.
.EXAMPLE
Get-FwFilter -Engine $engine -LayerKey "c38d57d1-05a7-4c33-904f-7fbceee60e82" -Sorted
Get firewall filters from layer key in a sorted order.
.EXAMPLE
Get-FwFilter -Engine $engine -Template $template
Get firewall filters based on a template.
#>
function Get-FwFilter {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [parameter(ParameterSetName="All")]
        [parameter(ParameterSetName="FromLayerKey")]
        [parameter(ParameterSetName="FromId")]
        [parameter(ParameterSetName="FromKey")]
        [parameter(ParameterSetName="FromAleLayer")]
        [parameter(ParameterSetName="FromTemplate")]
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromLayerKey")]
        [NtObjectManager.Utils.Firewall.FirewallLayerGuid]$LayerKey,
        [parameter(Mandatory, ParameterSetName="FromAleLayer")]
        [NtCoreLib.Net.Firewall.FirewallAleLayer]$AleLayer,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromLayer", ValueFromPipeline)]
        [NtCoreLib.Net.Firewall.FirewallLayer[]]$Layer,
        [parameter(Mandatory, ParameterSetName="FromId")]
        [uint64]$Id,
        [parameter(Mandatory, ParameterSetName="FromKey")]
        [guid]$Key,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromTemplate")]
        [NtCoreLib.Net.Firewall.FirewallFilterEnumTemplate]$Template,
        [parameter(ParameterSetName="FromLayerKey")]
        [parameter(ParameterSetName="FromAleLayer")]
        [switch]$Sorted,
        [parameter(ParameterSetName="FromLayerKey")]
        [parameter(ParameterSetName="FromAleLayer")]
        [switch]$IncludeDisabled
    )

    PROCESS {
        try {
            $Engine = Get-FwEngineSingleton -Engine $Engine

            switch($PSCmdlet.ParameterSetName) {
                "All" {
                    $Engine.EnumerateFilters() | Write-Output
                }
                "FromLayerKey" {
                    $Template = [NtCoreLib.Net.Firewall.FirewallFilterEnumTemplate]::new($LayerKey.Id)
                }
                "FromAleLayer" {
                    $Template = [NtCoreLib.Net.Firewall.FirewallFilterEnumTemplate]::new($AleLayer)
                }
                "FromLayer" {
                    foreach($l in $Layer) {
                        $l.EnumerateFilters() | Write-Output
                    }
                }
                "FromKey" {
                    $Engine.GetFilter($Key)
                }
                "FromId" {
                    $Engine.GetFilter($Id)
                }
            }
            if ($null -ne $Template) {
                if ($Sorted) {
                    $Template.Flags = $Template.Flags -bor "Sorted"
                }
                if ($IncludeDisabled) {
                    $Template.Flags = $Template.Flags -bor "IncludeDisabled"
                }
                $Engine.EnumerateFilters($Template) | Write-Output
            }
        } catch {
            Write-Error $_
        }
    }
}

Register-ArgumentCompleter -CommandName Get-FwFilter -ParameterName LayerKey -ScriptBlock $layer_completer

<#
.SYNOPSIS
Create a new template for enumerating filters.
.DESCRIPTION
This cmdlet creates a new template for enumerating filters, which can be used with Get-FwFilter.
.PARAMETER LayerKey
Specify the layer key. Can be a GUID or a well known name.
.PARAMETER AleLayer
Specify the ALE layer type.
.PARAMETER Flags
Specify enumeration flags.
.PARAMETER ActionType
Specify enumeration action type.
.PARAMETER Layer
Specify a layer object to query the filters from.
.PARAMETER Condition
Specify one or more conditions to check for when enumerating.
.PARAMETER Token
Specify the user identity for the filter.
.PARAMETER RemoteToken
Specify the remote user identity for the filter.
.PARAMETER Sorted
Specify to sort the filter output.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallFilterEnumTemplate
.EXAMPLE
New-FwFilterTemplate -LayerKey "c38d57d1-05a7-4c33-904f-7fbceee60e82"
Create a template for enumerating firewall filters from layer key.
#>
function New-FwFilterTemplate {
    [CmdletBinding(DefaultParameterSetName="FromLayerKey")]
    param(
        [parameter(Mandatory, ParameterSetName="FromLayerKey")]
        [NtObjectManager.Utils.Firewall.FirewallLayerGuid]$LayerKey,
        [parameter(Mandatory, ParameterSetName="FromAleLayer")]
        [NtCoreLib.Net.Firewall.FirewallAleLayer]$AleLayer,
        [NtCoreLib.Net.Firewall.FirewallFilterEnumFlags]$Flags = "None",
        [NtCoreLib.Net.Firewall.FirewallActionType]$ActionType = "All",
        [NtCoreLib.Net.Firewall.FirewallFilterCondition[]]$Condition,
        [switch]$Sorted
    )

    try {
        $template = switch($PSCmdlet.ParameterSetName) {
            "FromLayerKey" {
                [NtCoreLib.Net.Firewall.FirewallFilterEnumTemplate]::new($LayerKey.Id)
            }
            "FromAleLayer" {
                [NtCoreLib.Net.Firewall.FirewallFilterEnumTemplate]::new($AleLayer)
            }
        }
        if ($Sorted) {
            $Flags = $Flags -bor "Sorted"
        }
        $template.Flags = $Flags
        $template.ActionType = $ActionType
        if ($null -ne $Condition) {
            $template.Conditions.AddRange($Condition)
        }
        $template
    } catch {
        Write-Error $_
    }
}

Register-ArgumentCompleter -CommandName New-FwFilterTemplate -ParameterName LayerKey -ScriptBlock $layer_completer

<#
.SYNOPSIS
Add a firewall filter.
.DESCRIPTION
This cmdlet adds a firewall filter.
.PARAMETER Engine
The firewall engine to add to.
.PARAMETER LayerKey
Specify the layer key. Can be a GUID or a well known name.
.PARAMETER AleLayer
Specify the ALE layer type.
.PARAMETER SubLayerKey
Specify the sub-layer key
.PARAMETER Flags
Specify filters flags.
.PARAMETER ActionType
Specify action type.
.PARAMETER Key
Specify the filter's key.
.PARAMETER Id
Specify the filter's ID.
.PARAMETER Condition
A filter condition builder containing conditions to add.
.INPUTS
None
.OUTPUTS
uint64
#>
function Add-FwFilter {
    [CmdletBinding(DefaultParameterSetName="FromLayerKey")]
    param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 1)]
        [string]$Name,
        [string]$Description = "",
        [parameter(Mandatory, ParameterSetName="FromLayerKey")]
        [NtObjectManager.Utils.Firewall.FirewallLayerGuid]$LayerKey,
        [parameter(Mandatory, ParameterSetName="FromAleLayer")]
        [NtCoreLib.Net.Firewall.FirewallAleLayer]$AleLayer,
        [NtObjectManager.Utils.Firewall.FirewallSubLayerGuid]$SubLayerKey = "FWPM_SUBLAYER_UNIVERSAL",
        [guid]$Key = [guid]::Empty,
        [NtCoreLib.Net.Firewall.FirewallActionType]$ActionType = "Permit",
        [NtCoreLib.Net.Firewall.FirewallConditionBuilder]$Condition,
        [NtCoreLib.Net.Firewall.FirewallValue]$Weight = [NtCoreLib.Net.Firewall.FirewallValue]::Empty,
        [NtCoreLib.Net.Firewall.FirewallFilterFlags]$Flags = 0,
        [guid]$ProviderKey = [guid]::Empty
    )

    try {
        $builder = [NtCoreLib.Net.Firewall.FirewallFilterBuilder]::new()
        $builder.Name = $Name
        $builder.Description = $Description
        switch ($PSCmdlet.ParameterSetName) {
            "FromLayerKey" {
                $builder.LayerKey = $LayerKey.Id
            }
            "FromAleLayer" {
                $builder.LayerKey = Get-FwGuid -AleLayer $AleLayer
            }
        }

        $builder.SubLayerKey = $SubLayerKey.Id
        $builder.FilterKey = $Key
        $builder.ActionType = $ActionType
        if ($null -ne $Condition) {
            $builder.Conditions.AddRange($Condition.Conditions)
        }
        $builder.Weight = $Weight
        $builder.Flags = $Flags
        $builder.ProviderKey = $ProviderKey
        $Engine.AddFilter($builder)
    }
    catch {
        Write-Error $_
    }
}

Register-ArgumentCompleter -CommandName Add-FwFilter -ParameterName LayerKey -ScriptBlock $layer_completer
Register-ArgumentCompleter -CommandName Add-FwFilter -ParameterName SubLayerKey -ScriptBlock $sublayer_completer

<#
.SYNOPSIS
Delete a firewall filter.
.DESCRIPTION
This cmdlet deletes a firewall filter from an engine.
.PARAMETER Engine
The firewall engine.
.PARAMETER Key
Specify the filter's key.
.PARAMETER Id
Specify the filter's ID.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Remove-FwFilter -Engine $engine -Key "DB498708-9100-42F6-BC13-15E0A240D0ED"
Delete a filter by its key.
.EXAMPLE
Remove-FwFilter -Engine $engine -Id 12345
Delete a filter by its ID.
#>
function Remove-FwFilter {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, ParameterSetName="FromId")]
        [uint64]$Id,
        [parameter(Mandatory, ParameterSetName="FromKey")]
        [guid]$Key
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromKey" {
            $Engine.DeleteFilter($Key)
        }
        "FromId" {
            $Engine.DeleteFilter($Id)
        }
    }
}

<#
.SYNOPSIS
Format firewall filters.
.DESCRIPTION
This cmdlet formats a list of firewall filters.
.PARAMETER Filter
The list of filters to format.
.PARAMETER FormatSecurityDescriptor
Format any security descriptor condition values.
.PARAMETER Summary
Format the security descriptor in summary format.
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Format-FwFilter -Filter $fs
Format a list of firewall filters.
#>
function Format-FwFilter {
    [CmdletBinding(DefaultParameterSetName="NoSd")]
    param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Net.Firewall.FirewallFilter[]]$Filter,
        [parameter(Mandatory, ParameterSetName="FormatSd")]
        [switch]$FormatSecurityDescriptor,
        [parameter(ParameterSetName="FormatSd")]
        [switch]$Summary
    )

    PROCESS {
        foreach($f in $Filter) {
            Write-Output "Name       : $($f.Name)"
            Write-Output "Action Type: $($f.ActionType)"
            Write-Output "Key        : $($f.Key)"
            Write-Output "Id         : $($f.FilterId)"
            Write-Output "Description: $($f.Description)"
            Write-Output "Layer      : $($f.LayerKeyName)"
            Write-Output "Sub Layer  : $($f.SubLayerKeyName)"
            Write-Output "Flags      : $($f.Flags)"
            Write-Output "Weight     : $($f.EffectiveWeight)"
            if ($f.IsCallout) {
                Write-Output "Callout Key: $($f.CalloutKeyName)"
            }
            if ($f.Conditions.Count -gt 0) {
                Write-Output "Conditions :"
                Format-ObjectTable -InputObject $f.Conditions
                if ($FormatSecurityDescriptor) {
                    foreach($cond in $f.Conditions) {
                        if ($cond.Value.Value -is [NtCoreLib.Security.Authorization.SecurityDescriptor]) {
                            Format-NtSecurityDescriptor -SecurityDescriptor $cond.Value.Value -DisplayPath $cond.FieldKeyName -Summary:$Summary
                        }
                    }
                }
            }
            Write-Output ""
        }
    }
}

<#
.SYNOPSIS
Create a firewall condition builder.
.DESCRIPTION
This cmdlet creates a new firewall condition builder. Use Add-FwCondition to add a condition to it.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallConditionBuilder
.EXAMPLE
New-FwConditionBuilder
Create a condition builder.
.EXAMPLE
$builder = New-FwConditionBuilder | Add-FwCondition -Filename "c:\windows\notepad.exe" -PassThru
Create a filter condition builder and add a filter condition for the notepad executable.
#>
function New-FwConditionBuilder {
    [NtCoreLib.Net.Firewall.FirewallConditionBuilder]::new()
}

<#
.SYNOPSIS
Add a firewall condition to a template.
.DESCRIPTION
This cmdlet adds a firewall condition for a template.
.PARAMETER Builder
The condition builder/template to add the condition to.
.PARAMETER MatchType
The match operation for the condition.
.PARAMETER Filename
The path to an executable file to match.
.PARAMETER AppId
The path to an executable file to match using the native format.
.PARAMETER UserId
The security descriptor to check against the local user ID.
.PARAMETER RemoteUserId
The security descriptor to check against the remote user ID.
.PARAMETER ProtocolType
The type of IP protocol.
.PARAMETER IPAddress
The remote IP address.
.PARAMETER Port
The remote TCP/UDP port.
.PARAMETER LocalIPAddress
The local IP address.
.PARAMETER LocalPort
The local TCP/UDP port.
.PARAMETER IPAddress
The local IP address.
.PARAMETER Port
The local TCP/UDP port.
.PARAMETER Token
The token for a token information condition for user ID.
.PARAMETER RemoteToken
The token for a token information condition for remote user ID.
.PARAMETER MachineToken
The token for a token information condition for remote machine ID.
.PARAMETER PackageSid
The token's package SID.
.PARAMETER ConditionFlags
Specify condition flags to match.
.PARAMETER Process
Specify process to populate from. Adds token information and app ID.
.PARAMETER ProcessId
Specify process ID to populate from. Adds token information and app ID.
.PARAMETER PassThru
Pass through the condition builder/template.
.INPUTS
NtCoreLib.Net.Firewall.FirewallConditionBuilder
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallConditionBuilder
.EXAMPLE
Add-FwCondition $builder -Filename "c:\windows\notepad.exe"
Add a filter condition for the notepad executable.
.EXAMPLE
Add-FwCondition $builder -Filename "c:\windows\notepad.exe" -MatchType NotEqual
Add a filter condition which doesn't match the notepad executable.
.EXAMPLE
Add-FwCondition $builder -ProtocolType Tcp
Add a filter condition for the TCP protocol.
#>
function Add-FwCondition {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Net.Firewall.FirewallConditionBuilder]$Builder,
        [NtCoreLib.Net.Firewall.FirewallMatchType]$MatchType = "Equal",
        [switch]$PassThru,
        [parameter(Mandatory, ParameterSetName="FromFilename")]
        [string]$Filename,
        [parameter(Mandatory, ParameterSetName="FromAppId")]
        [string]$AppId,
        [parameter(Mandatory, ParameterSetName="FromUserId")]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$UserId,
        [parameter(Mandatory, ParameterSetName="FromRemoteUserId")]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$RemoteUserId,
        [parameter(Mandatory, ParameterSetName="FromProtocolType")]
        [System.Net.Sockets.ProtocolType]$ProtocolType,
        [parameter(Mandatory, ParameterSetName="FromConditionFlags")]
        [NtCoreLib.Net.Firewall.FirewallConditionFlags]$ConditionFlags,
        [parameter(ParameterSetName="FromRemoteEndpoint")]
        [System.Net.IPAddress]$IPAddress,
        [parameter(ParameterSetName="FromRemoteEndpoint")]
        [int]$Port = -1,
        [parameter(ParameterSetName="FromLocalEndpoint")]
        [System.Net.IPAddress]$LocalIPAddress,
        [parameter(ParameterSetName="FromLocalEndpoint")]
        [int]$LocalPort = -1,
        [parameter(Mandatory, ParameterSetName="FromToken")]
        [NtCoreLib.NtToken]$Token,
        [parameter(Mandatory, ParameterSetName="FromRemoteToken")]
        [NtCoreLib.NtToken]$RemoteToken,
        [parameter(Mandatory, ParameterSetName="FromMachineToken")]
        [NtCoreLib.NtToken]$MachineToken,
        [parameter(Mandatory, ParameterSetName="FromPackageSid")]
        [NtObjectManager.Utils.Firewall.FirewallPackageSid]$PackageSid,
        [parameter(Mandatory, ParameterSetName="FromProcess")]
        [NtCoreLib.NtProcess]$Process,
        [parameter(Mandatory, ParameterSetName="FromProcessID")]
        [alias("pid")]
        [int]$ProcessId,
        [parameter(Mandatory, ParameterSetName="FromNetEventType")]
        [NtCoreLib.Net.Firewall.FirewallNetEventType]$NetEventType
    )

    try {
        switch($PSCmdlet.ParameterSetName) {
            "FromFilename" {
                $Builder.AddFilename($MatchType, $Filename)
            }
            "FromAppId" {
                $Builder.AddAppId($MatchType, $AppId)
            }
            "FromUserId" {
                $Builder.AddUserId($MatchType, $UserId)
            }
            "FromRemoteUserId" {
                $Builder.AddRemoteUserId($MatchType, $RemoteUserId)
            }
            "FromProtocolType" {
                $Builder.AddProtocolType($MatchType, $ProtocolType)
            }
            "FromConditionFlags" {
                $Builder.AddConditionFlags($MatchType, $ConditionFlags)
            }
            "FromRemoteEndpoint" {
                if ($null -ne $IPAddress) {
                    $Builder.AddIpAddress($MatchType, $true, $IPAddress)
                }
                if ($Port -ge 0) {
                    $Builder.AddPort($MatchType, $true, $Port)
                }
            }
            "FromLocalEndpoint" {
                if ($null -ne $LocalIPAddress) {
                    $Builder.AddIpAddress($MatchType, $false, $LocalIPAddress)
                }
                if ($LocalPort -ge 0) {
                    $Builder.AddPort($MatchType, $false, $LocalPort)
                }
            }
            "FromToken" {
                $Builder.AddUserToken($MatchType, $Token)
            }
            "FromRemoteToken" {
                $Builder.AddRemoteUserToken($MatchType, $RemoteToken)
            }
            "FromMachineToken" {
                $Builder.AddRemoteMachineToken($MatchType, $MachineToken)
            }
            "FromPackageSid" {
                $Builder.AddPackageSid($MatchType, $PackageSid.Sid)
            }
            "FromProcess" {
                $Builder.AddProcess($MatchType, $Process)
            }
            "FromProcessId" {
                $Builder.AddProcess($MatchType, $ProcessId)
            }
            "FromNetEventType" {
                $Builder.AddNetEventType($MatchType, $NetEventType)
            }
        }
        if ($PassThru) {
            $Builder
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get a firewall known GUID from a name.
.DESCRIPTION
This cmdlet gets a GUID from a name for well-known layer or sub-layer names.
.PARAMETER LayerName
The name of the layer.
.PARAMETER SubLayerName
The name of the sub-layer.
.PARAMETER AleLayer
The ALE layer type.
.INPUTS
None
.OUTPUTS
Guid
.EXAMPLE
Get-FwGuid -LayerName FWPM_LAYER_INBOUND_IPPACKET_V4
Get the GUID for a layer name.
.EXAMPLE
Get-FwGuid -AleLayer ConnectV4
Get the GUID for the ALE IPv4 connect layer.
.EXAMPLE
Get-FwGuid -SubLayerName FWPM_SUBLAYER_UNIVERSAL
Get the GUID for a sub-layer name.
#>
function Get-FwGuid {
    [CmdletBinding(DefaultParameterSetName="FromLayerName")]
    Param(
        [parameter(Mandatory, ParameterSetName="FromLayerName")]
        [string]$LayerName,
        [parameter(Mandatory, ParameterSetName="FromAleLayer")]
        [NtCoreLib.Net.Firewall.FirewallAleLayer]$AleLayer,
        [parameter(Mandatory, ParameterSetName="FromSubLayerName")]
        [string]$SubLayerName
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromLayerName" {
            [NtCoreLib.Net.Firewall.FirewallUtils]::GetKnownLayerGuid($LayerName)
        }
        "FromAleLayer" {
            [NtCoreLib.Net.Firewall.FirewallUtils]::GetLayerGuidForAleLayer($AleLayer)
        }
        "FromSubLayerName" {
            [NtCoreLib.Net.Firewall.FirewallUtils]::GetKnownSubLayerGuid($SubLayerName)
        }
    }
}

Register-ArgumentCompleter -CommandName Get-FwGuid -ParameterName LayerName -ScriptBlock $layer_completer
Register-ArgumentCompleter -CommandName Get-FwGuid -ParameterName SubLayerName -ScriptBlock $sublayer_completer

<#
.SYNOPSIS
Get an ALE endpoint.
.DESCRIPTION
This cmdlet gets a firewall ALE endpoint from an engine.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER Id
Specify the ALE endpoint ID.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallAleEndpoint[]
.EXAMPLE
Get-FwAleEndpoint -Engine $engine
Get all firewall ALE endpoints.
.EXAMPLE
Get-FwAleEndpoint -Engine $engine -Id 12345
Get the firewall ALE endpoint with ID 12345.
#>
function Get-FwAleEndpoint {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromId")]
        [uint64]$Id
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Engine.EnumerateAleEndpoints() | Write-Output
            }
            "FromId" {
                $Engine.GetAleEndpoint($Id)
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get token from firewall.
.DESCRIPTION
This cmdlet gets an access token from the firewall based on the modified ID.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER ModifiedId
Specify the token modified ID.
.PARAMETER AleEndpoint
Specify an ALE endpoint.
.PARAMETER Access
Specify Token access rights.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtToken
.EXAMPLE
Get-FwToken -Engine $engine -ModifiedId 00000000-00012345
Get token from its modified ID.
.EXAMPLE
Get-FwToken -Engine $engine -AleEndpoint $ep
Get token from an ALE endpoint.
#>
function Get-FwToken {
    [CmdletBinding(DefaultParameterSetName="FromLuid")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromEndpoint")]
        [NtCoreLib.Net.Firewall.FirewallAleEndpoint]$AleEndpoint,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromLuid")]
        [NtCoreLib.Luid]$ModifiedId,
        [NtCoreLib.TokenAccessRights]$Access = "Query"
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine
        if ($PSCmdlet.ParameterSetName -eq "FromEndpoint") {
            $ModifiedId = $AleEndpoint.LocalTokenModifiedId
        }
        $Engine.OpenToken($ModifiedId, $Access)
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get an IKE security association.
.DESCRIPTION
This cmdlet gets an IKE security association from an engine. It can return a specific security association or all of them.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER Id
Specify the security association ID.
.PARAMETER SaLookupContext
Specify the the security association lookup context.
.PARAMETER Socket
Specify a secured socket to lookup the security association.
.PARAMETER Client
Specify a secured TCP client to lookup the security association.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.IkeSecurityAssociation[]
.EXAMPLE
Get-IkeSecurityAssociation -Engine $engine
Get all IKE security associations.
.EXAMPLE
Get-IkeSecurityAssociation -Engine $engine -Id 1234
Get an IKE security associations from an ID.
.EXAMPLE
Get-IkeSecurityAssociation -Engine $engine -Id 1234 -SaLookupContext "eebecc03-ced4-4380-819a-2734397b2b74"
Get an IKE security associations from an ID and lookup context.
.EXAMPLE
Get-IkeSecurityAssociation -Engine $engine -Socket $sock
Get an IKE security associations from a secured socket.
.EXAMPLE
Get-IkeSecurityAssociation -Engine $engine -Socket $sock -PeerAddress $ep
Get an IKE security associations from a secured socket with a specified peer address.
.EXAMPLE
Get-IkeSecurityAssociation -Engine $engine -Client $client
Get an IKE security associations from a secured TCP client.
#>
function Get-IkeSecurityAssociation {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromId")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromIdAndContext")]
        [uint64]$Id,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromIdAndContext")]
        [guid]$SaLookupContext,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromSocket")]
        [System.Net.Sockets.Socket]$Socket,
        [Parameter(ParameterSetName="FromSocket")]
        [System.Net.IPEndPoint]$PeerAddress,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromTcpClient")]
        [System.Net.Sockets.TcpClient]$Client
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine

        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Engine.EnumerateIkeSecurityAssociations() | Write-Output
            }
            "FromId" {
                $Engine.GetIkeSecurityAssociation($Id, $null)
            }
            "FromIdAndContext" {
                $Engine.GetIkeSecurityAssociation($Id, $SaLookupContext)
            }
            "FromSocket" {
                $r = Get-SocketSecurity -Socket $Socket -PeerAddress $PeerAddress
                $Engine.GetIkeSecurityAssociation($r.MmSaId, $r.SaLookupContext)
            }
            "FromTcpClient" {
                $r = Get-SocketSecurity -Client $Client
                $Engine.GetIkeSecurityAssociation($r.MmSaId, $r.SaLookupContext)
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get all firewall sessions.
.DESCRIPTION
This cmdlet gets all firewall sessions from an engine.
.PARAMETER Engine
The firewall engine to query.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallSession[]
.EXAMPLE
Get-FwSession -Engine $engine
Get all firewall sessions.
#>
function Get-FwSession {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Engine.EnumerateSessions() | Write-Output
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get all firewall network events.
.DESCRIPTION
This cmdlet gets all firewall network events from an engine.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER Template
Filter template for the network events.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallNetEvent[]
.EXAMPLE
Get-FwNetEvent -Engine $engine
Get all firewall network events.
#>
function Get-FwNetEvent {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [NtCoreLib.Net.Firewall.FirewallNetEventEnumTemplate]$Template
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Engine.EnumerateNetEvents($Template) | Write-Output
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Creates a network event listener.
.DESCRIPTION
This cmdlet creates a network event listenr from an engine. You pass the result to Read-FwNetEvent in a loop to read the events.
.PARAMETER Engine
The engine to create from.
.PARAMETER Template
Filter template for the network events.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallNetEventListener
.EXAMPLE
New-FwNetEventListener
Create a new firewall network event listener.
#>
function New-FwNetEventListener {
    [CmdletBinding()]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [NtCoreLib.Net.Firewall.FirewallNetEventEnumTemplate]$Template
    )
    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine

        $opt = Get-FwEngineOption -Engine $Engine -CollectNetEvents
        if (!$opt) {
            Write-Warning "CollectNetEvents option is not enabled. No events will be collected."
        }

        $Engine.SubscribeNetEvents($Template)
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Read a live firewall network events.
.DESCRIPTION
This cmdlet reads a live firewall network events from an engine.
.PARAMETER Listener
The firewall listener to read from.
.PARAMETER TimeoutMs
Specify a read timeout in milliseconds. -1 waits indefinitely.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallNetEvent
.EXAMPLE
Read-FwNetEvent -Listener $l
Read a live firewall network event.
#>
function Read-FwNetEvent {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Net.Firewall.FirewallNetEventListener]$Listener,
        [int]$TimeoutMs = -1
    )

    $time_remaining = $TimeoutMs
    try {
        $ev = $null
        while($true) {
            $ev = $listener.ReadEvent(1000)
            if ($null -ne $ev) {
                break
            }
            if ($TimeoutMs -eq -1) {
                continue
            }
            $time_remaining -= 1000
            if ($time_remaining -le 0) {
                break;
            }
        }
        $ev
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Starts a network event listener.
.DESCRIPTION
This cmdlet starts a network event listener from an engine. It will read network events and print them to the console. It can also
capture the events into a variable.
.PARAMETER Engine
The engine to listen from.
.PARAMETER Variable
The name of a variable to put the read network events into.
.PARAMETER Template
Filter template for the network events.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Start-FwNetEventListener
Start a new firewall network event listener.
.EXAMPLE
Start-FwNetEventListener -Variable "events"
Start a new firewall network event listener and store the captured events in a variable.
#>
function Start-FwNetEventListener {
    [CmdletBinding()]
    param(
        [NtCoreLib.Net.Firewall.FirewallNetEventEnumTemplate]$Template,
        [string]$Variable,
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine
    )

    try {
        Use-NtObject($listener = New-FwNetEventListener -Engine $Engine -Template $Template) {
            if ($null -eq $listener) {
                return
            }
            $psvar = if ("" -ne $Variable) {
                Set-Variable -Name $Variable -Value @() -Scope global
                Get-Variable -Name $Variable
            }
            $shown_header = $false
            while($true) {
                $ev = Read-FwNetEvent -Listener $listener
                if ($null -eq $ev) {
                    break
                }
                if ($null -ne $psvar) {
                    $psvar.Value += @($ev)
                }
                Format-ObjectTable $ev -HideTableHeaders:$shown_header -NoTrailingLine | Out-Host
                $shown_header = $true
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Create a new template for enumerating network events.
.DESCRIPTION
This cmdlet creates a new template for enumerating network events, which can be used with Get-FwNetEvent and Start-FwNetEventListener.
.PARAMETER
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallNetEventEnumTemplate
.EXAMPLE
New-FwNetEventTemplate -StartTime ([datetime]::now.AddHours(-1))
Create a template for enumerating net events starting one hour ago.
#>
function New-FwNetEventTemplate {
    [CmdletBinding()]
    param(
        [datetime]$StartTime = [datetime]::FromFileTime(0),
        [datetime]$EndTime = [datetime]::MaxValue,
        [NtCoreLib.Net.Firewall.FirewallFilterCondition[]]$Condition
    )

    try {
        $template = [NtCoreLib.Net.Firewall.FirewallNetEventEnumTemplate]::new()
        $template.StartTime = $StartTime
        $template.EndTime = $EndTime
        if ($null -ne $Condition) {
            $template.Conditions.AddRange($Condition)
        }
        $template
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get an IPsec security association context.
.DESCRIPTION
This cmdlet gets an IPsec security association context from an engine.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER Id
Specify the IPsec security association context ID.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.IPsecSecurityAssociationContext[]
.EXAMPLE
Get-IPsecSaContext -Engine $engine
Get all security association context.
.EXAMPLE
Get-IPsecSaContext -Engine $engine -Id 12345
Get the security association context with ID 12345.
#>
function Get-IPsecSaContext {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromId")]
        [uint64]$Id
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Engine.EnumerateIPsecSecurityAssociationContexts() | Write-Output
            }
            "FromId" {
                $Engine.GetIPsecSecurityAssociationContext($Id)
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get a firewall engine option.
.DESCRIPTION
This cmdlet gets a firewall engine option.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER Option
Specify the option to query.
.PARAMETER CollectNetEvents
Specify to get the CollectNetEvents option.
.PARAMETER NetEventMatchAnyKeywords
Specify to get the NetEventMatchAnyKeywords option.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallValue
.EXAMPLE
Get-FwEngineOption -Option MonitorIPsecConnections
Get MonitorIPsecConnections option.
.EXAMPLE
Get-FwEngineOption -CollectNetEvents
Get CollectNetEvents option.
.EXAMPLE
Get-FwEngineOption -NetEventMatchAnyKeywords
Get NetEventMatchAnyKeywords option.
#>
function Get-FwEngineOption {
    [CmdletBinding(DefaultParameterSetName="FromOption")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromOption")]
        [NtCoreLib.Net.Firewall.FirewallEngineOption]$Option,
        [parameter(Mandatory, ParameterSetName="FromCollect")]
        [switch]$CollectNetEvents,
        [parameter(Mandatory, ParameterSetName="FromKeywords")]
        [switch]$NetEventMatchAnyKeywords
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine
        switch($PSCmdlet.ParameterSetName) {
            "FromOption" {
                $Engine.GetOption($Option)
            }
            "FromCollect" {
                $Engine.GetCollectNetEvents()
            }
            "FromKeywords" {
                $Engine.GetNetEventMatchAnyKeywords()
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get a firewall engine option.
.DESCRIPTION
This cmdlet sets a firewall engine option.
.PARAMETER Engine
The firewall engine to set.
.PARAMETER Option
Specify the option to set.
.PARAMETER Value
Specify the value to set.
.PARAMETER CollectNetEvents
Specify to set the CollectNetEvents option.
.PARAMETER NetEventMatchAnyKeywords
Specify to set the NetEventMatchAnyKeywords option.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-FwEngineOption -Option MonitorIPsecConnections -Value $val
Set MonitorIPsecConnections option.
.EXAMPLE
Set-FwEngineOption -CollectNetEvents $true
Set CollectNetEvents option to true.
.EXAMPLE
Set-FwEngineOption -NetEventMatchAnyKeywords CapabilityDrop
Get NetEventMatchAnyKeywords option.
#>
function Set-FwEngineOption {
    [CmdletBinding(DefaultParameterSetName="FromOption")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromOption")]
        [NtCoreLib.Net.Firewall.FirewallEngineOption]$Option,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromOption")]
        [NtCoreLib.Net.Firewall.FirewallValue]$Value,
        [parameter(Mandatory, ParameterSetName="FromCollect")]
        [bool]$CollectNetEvents,
        [parameter(Mandatory, ParameterSetName="FromKeywords")]
        [NtCoreLib.Net.Firewall.FirewallNetEventKeywords]$NetEventMatchAnyKeywords
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine
        switch($PSCmdlet.ParameterSetName) {
            "FromOption" {
                $Engine.SetOption($Option, $Value)
            }
            "FromCollect" {
                $Engine.SetCollectNetEvents($CollectNetEvents)
            }
            "FromKeywords" {
                $Engine.SetNetEventMatchAnyKeywords($NetEventMatchAnyKeywords)
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get a firewall callouts.
.DESCRIPTION
This cmdlet gets a firewall callout from an engine. It can return a specific callout or all callouts.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER Key
Specify the callout key.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallCallout[]
.EXAMPLE
Get-FwCallout
Get all firewall callouts.
.EXAMPLE
Get-FwCallout -Key "eebecc03-ced4-4380-819a-2734397b2b74"
Get firewall callout from key.
#>
function Get-FwCallout {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, ParameterSetName="FromKey")]
        [NtObjectManager.Utils.Firewall.FirewallCalloutGuid]$Key
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine

        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Engine.EnumerateCallouts() | Write-Output
            }
            "FromKey" {
                $Engine.GetCallout($Key.Id)
            }
        }
    } catch {
        Write-Error $_
    }
}

Register-ArgumentCompleter -CommandName Get-FwCallout -ParameterName Key -ScriptBlock $callout_completer

<#
.SYNOPSIS
Get a firewall provider.
.DESCRIPTION
This cmdlet gets a firewall provider from an engine. It can return a specific provider or all providers.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER Key
Specify the provider key.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallSubLayer[]
.EXAMPLE
Get-FwProvider
Get all firewall providers.
#>
function Get-FwProvider {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, ParameterSetName="FromKey")]
        [Guid]$Key
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine

        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Engine.EnumerateProviders() | Write-Output
            }
            "FromKey" {
                $Engine.GetProvider($Key)
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Exports keys to a Kerberos KeyTab file file.
.DESCRIPTION
This cmdlet exports keys to a Kerberos KeyTab file file.
.PARAMETER Key
List of keys to write to the file.
.PARAMETER Path
The path to the file to export.
.INPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey
.OUTPUTS
None
#>
function Export-KerberosKeyTab {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Path,
        [Parameter(Position = 1, Mandatory, ValueFromPipeline)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey[]]$Key
    )

    BEGIN {
        $keys = @()
    }

    PROCESS {
        foreach($k in $Key) {
            $keys += $k
        }
    }

    END {
        $key_arr = [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey[]]$keys
        $keytab = [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosUtils]::GenerateKeyTabFile($key_arr)
        Write-BinaryFile -Path $Path -Byte $keytab
    }
}

<#
.SYNOPSIS
Imports a Kerberos KeyTab file into a list of keys.
.DESCRIPTION
This cmdlet imports a Kerberos KeyTab file into a list of keys.
.PARAMETER Path
The path to the file to import.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey[]
#>
function Import-KerberosKeyTab {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Path
    )

    $Path = Resolve-Path -Path $Path -ErrorAction Stop
    [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosUtils]::ReadKeyTabFile($Path) | Write-Output
}

<#
.SYNOPSIS
Create a new Kerberos keytab file from a user's credentials.
.DESCRIPTION
This cmdlet creates a new Kerberos keytab file from a user's credentials.
.PARAMETER Credential
Credentials for the authentication.
.PARAMETER ReadCredential
Specify to read the credentials from the console if not specified explicitly.
.PARAMETER UserName
The username to use.
.PARAMETER Domain
The domain to use.
.PARAMETER Password
The password to use.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey[]
#>
function New-KerberosKeyTab {
    [CmdletBinding(DefaultParameterSetName="FromCreds")]
    Param(
        [Parameter(Mandatory, ParameterSetName="FromCreds")]
        [NtCoreLib.Win32.Security.Authentication.AuthenticationCredentials]$Credential,
        [Parameter(ParameterSetName="FromParts")]
        [switch]$ReadCredential,
        [Parameter(ParameterSetName="FromParts")]
        [string]$UserName,
        [Parameter(ParameterSetName="FromParts")]
        [string]$Domain,
        [Parameter(ParameterSetName="FromParts")]
        [alias("SecurePassword")]
        [NtObjectManager.Utils.PasswordHolder]$Password
    )

    if ($PSCmdlet.ParameterSetName -eq "FromParts") {
        if ($ReadCredential) {
            $Credential = Read-LsaCredential -UserName $UserName -Domain $Domain `
                    -Password $Password
        } else {
            $Credential = Get-LsaCredential -UserName $UserName -Domain $Domain `
                    -Password $Password
        }
    }

    [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosKeySet]::GetKeyTab($Credential) | Write-Output
}

<#
.SYNOPSIS
Gets a Kerberos Key from a raw key or password.
.DESCRIPTION
This cmdlet gets a Kerberos Key from a raw key or password.
.PARAMETER Password
The password to convert to a key.
.PARAMETER KeyType
The key encryption type.
.PARAMETER Iterations
The number of iterations for the key derivation.
.PARAMETER Principal
The principal associated with the key.
.PARAMETER Salt
The salt for the key, if not specified will try and derive from the principal.
.PARAMETER Base64Key
The key as a base64 string.
.PARAMETER HexKey
The key as a hex string.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey
#>
function Get-KerberosKey {
    [CmdletBinding(DefaultParameterSetName="FromPassword")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromPassword")]
        [NtObjectManager.Utils.PasswordHolder]$Password,
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromKey")]
        [byte[]]$Key,
        [Parameter(Mandatory, ParameterSetName="FromBase64Key")]
        [string]$Base64Key,
        [Parameter(Mandatory, ParameterSetName="FromHexKey")]
        [string]$HexKey,
        [Parameter(Position = 1, Mandatory, ParameterSetName="FromPassword")]
        [Parameter(Position = 1, Mandatory, ParameterSetName="FromKey")]
        [Parameter(Mandatory, ParameterSetName="FromBase64Key")]
        [Parameter(Mandatory, ParameterSetName="FromHexKey")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosEncryptionType]$KeyType,
        [Parameter(ParameterSetName="FromPassword")]
        [int]$Interations = 4096,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosNameType]$NameType = "PRINCIPAL",
        [Parameter(Position = 2, Mandatory, ParameterSetName="FromPassword")]
        [Parameter(Position = 2, ParameterSetName="FromKey")]
        [Parameter(ParameterSetName="FromBase64Key")]
        [Parameter(ParameterSetName="FromHexKey")]
        [string]$Principal,
        [Parameter(ParameterSetName="FromPassword")]
        [string]$Salt,
        [uint32]$Version = 1,
        [Parameter(ParameterSetName="FromKey")]
        [Parameter(ParameterSetName="FromBase64Key")]
        [Parameter(ParameterSetName="FromHexKey")]
        [DateTime]$Timestamp = [DateTime]::Now
    )

    try {
        $k = switch($PSCmdlet.ParameterSetName) {
            "FromPassword" {
                [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]::DeriveKey($KeyType, $Password.ToPlainText(), $Interations, $NameType, $Principal, $Salt, $Version)
            }
            "FromKey" {
                [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]::new($KeyType, $Key, $NameType, $Principal, $Timestamp, $Version)
            }
            "FromBase64Key" {
                $Key = [System.Convert]::FromBase64String($Base64Key)
                [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]::new($KeyType, $Key, $NameType, $Principal, $Timestamp, $Version)
            }
            "FromHexKey" {
                $Key = ConvertFrom-HexDump -Hex $HexKey
                [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]::new($KeyType, $Key, $NameType, $Principal, $Timestamp, $Version)
            }
        }
        $k | Write-Output
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Create a new random kerberos key.
.DESCRIPTION
This cmdlet creates a new Kerberos Key.
.PARAMETER KeyType
The key encryption type.
.PARAMETER Key
The existing key to use the encryption type from.
.PARAMETER Name
The principal name to use.
.PARAMETER Realm
The realm to use.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey
#>
function New-KerberosKey {
    [CmdletBinding(DefaultParameterSetName="FromEncType")]
    Param(
        [Parameter(Mandatory, ParameterSetName="FromEncType", Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosEncryptionType]$KeyType,
        [Parameter(Mandatory, ParameterSetName="FromKey", Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$Key,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$Name,
        [string]$Realm
    )

    if ($PSCmdlet.ParameterSetName -eq "FromKey") {
        $Key.GenerateKey($Name, $Realm)
    } else {
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]::GenerateKey($KeyType, $Name, $Realm)
    }
}

<#
.SYNOPSIS
Get Kerberos Ticket.
.DESCRIPTION
This cmdlet gets a kerberos Ticket, or multiple tickets.
.PARAMETER LogonId
Specify a logon ID to query for tickets.
.PARAMETER LogonSession
Specify a logon session to query for tickets.
.PARAMETER TargetName
Specify a target name to query for a ticket. If it doesn't exist get a new one.
.PARAMETER CacheOnly
Specify to only lookup the TargetName in the cache.
.PARAMETER CredHandle
Specify a credential handle to query the ticket from.
.PARAMETER Cache
Specify to get a ticket from a local cache.
.PARAMETER InfoOnly
Specify to only return information from the cache not the tickets themselves.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosExternalTicket
#>
function Get-KerberosTicket {
    [CmdletBinding(DefaultParameterSetName="CurrentLuid")]
    Param(
        [Parameter(Position = 0, ParameterSetName="FromTarget", Mandatory)]
        [Parameter(Position = 0, ParameterSetName="FromLocalCache", Mandatory)]
        [string]$TargetName,
        [Parameter(Position = 0, ParameterSetName="FromLuid", Mandatory)]
        [Parameter(Position = 1, ParameterSetName="FromTarget")]
        [NtCoreLib.Luid]$LogonId = [NtCoreLib.Luid]::new(0),
        [Parameter(Position = 0, ParameterSetName="FromLogonSession", ValueFromPipeline, Mandatory)]
        [NtCoreLib.Win32.Security.Authentication.LogonSession[]]$LogonSession,
        [Parameter(ParameterSetName="FromTarget")]
        [NtCoreLib.Win32.Security.Authentication.CredentialHandle]$CredHandle,
        [Parameter(ParameterSetName="FromLocalCache", Mandatory)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]$Cache,
        [Parameter(ParameterSetName="FromTarget")]
        [Parameter(ParameterSetName="FromLocalCache")]
        [switch]$CacheOnly,
        [Parameter(ParameterSetName="FromLuid")]
        [Parameter(ParameterSetName="CurrentLuid")]
        [Parameter(ParameterSetName="FromLogonSession")]
        [switch]$InfoOnly,
        [Parameter(ParameterSetName="FromTarget")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosRetrieveTicketFlags]$Flags = 0,
        [Parameter(ParameterSetName="FromTarget")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketFlags]$TicketFlags = 0,
        [Parameter(ParameterSetName="FromTarget")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosEncryptionType]$EncryptionType = 0
    )

    PROCESS {
        try {
            switch($PSCmdlet.ParameterSetName) {
                "CurrentLuid" {
                    if ($InfoOnly) {
                        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCacheInfo() | Write-Output
                    } else {
                        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCache() | Write-Output
                    }
                }
                "FromLuid" {
                    if ($InfoOnly) {
                        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCacheInfo($LogonId) | Write-Output
                    } else {
                        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCache($LogonId) | Write-Output
                    }
                }
                "FromLogonSession" {
                    foreach($l in $LogonSession) {
                        if ($InfoOnly) {
                            [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCacheInfo($l.LogonId) | Write-Output
                        } else {
                            [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCache($l.LogonId) | Write-Output
                        }
                    }
                }
                "FromTarget" {
                    $Flags = $Flags -bor "AsKerbCred"
                    if ($CacheOnly) {
                        $Flags = $Flags -bor "UseCacheOnly"
                    }

                    [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::RetrieveTicket($TargetName, $LogonId, $CredHandle, $Flags, $TicketFlags, $EncryptionType) | Write-Output
                }
                "FromLocalCache" {
                    $Cache.GetTicket($TargetName, $CacheOnly)
                }
            }
        } catch {
            Write-Error $_
        }
    }
}

<#
.SYNOPSIS
Format a Kerberos Ticket.
.DESCRIPTION
This cmdlet formats a kerberos Ticket, or multiple tickets.
.PARAMETER Ticket
Specify the ticket to format.
.INPUTS
None
.OUTPUTS
string
#>
function Format-KerberosTicket {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicket]$Ticket
    )

    PROCESS {
        $Ticket.Format()
    }
}

<#
.SYNOPSIS
Create a new Kerberos checksum.
.DESCRIPTION
This cmdlet creates a new Kerberos checksum. It defaults to creating a GSSAPI checksum
which is the most common type.
.PARAMETER Credential
Specify a Kerberos credentials to use for delegation.
.PARAMETER ContextFlags
Specify context flags for the checksum.
.PARAMETER ChannelBinding
Specify the channel binding.
.PARAMETER Extenstion
Specify additional extension data.
.PARAMETER DelegationOptionIdentifier
Specify the delegation options identifier.
.PARAMETER Type
Specify the type of checksum.
.PARAMETER Checksum
Specify the checksum value.
.PARAMETER Key
Specify a kerberos key to generate the checksum.
.PARAMETER KeyUsage
Specify the key usage for the checksum calculation.
.PARAMETER Data
Specify the data to checksum.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosChecksum
#>
function New-KerberosChecksum {
    [CmdletBinding(DefaultParameterSetName="FromGssApi")]
    Param(
        [Parameter(ParameterSetName="FromGssApi")]
        [byte[]]$ChannelBinding,
        [Parameter(ParameterSetName="FromGssApi")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosChecksumGSSApiFlags]$ContextFlags = 0,
        [Parameter(ParameterSetName="FromGssApi")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosCredential]$Credential,
        [Parameter(ParameterSetName="FromGssApi")]
        [int]$DelegationOptionIdentifier = 0,
        [Parameter(ParameterSetName="FromGssApi")]
        [byte[]]$Extension,
        [Parameter(Mandatory, ParameterSetName="FromRaw")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosChecksumType]$Type,
        [Parameter(Mandatory, ParameterSetName="FromRaw")]
        [byte[]]$Checksum,
        [Parameter(Mandatory, ParameterSetName="FromKey")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$Key,
        [Parameter(Mandatory, ParameterSetName="FromKey")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosKeyUsage]$KeyUsage,
        [Parameter(Mandatory, ParameterSetName="FromKey")]
        [byte[]]$Data
    )

    PROCESS {
        switch($PSCmdlet.ParameterSetName) {
            "FromGssApi" {
                [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosChecksumGSSApi]::new($ContextFlags, $ChannelBinding, $DelegationOptionIdentifier, $Credential, $Extension)
            }
            "FromRaw" {
                [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosChecksum]::new($Type, $Checksum)
            }
            "FromKey" {
                [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosChecksum]::Create($Key, $Data, $KeyUsage)
            }
        }
    }
}

<#
.SYNOPSIS
Create a new Kerberos principal name.
.DESCRIPTION
This cmdlet creates a new Kerberos principal name.
.PARAMETER Type
Specify the type of principal name.
.PARAMETER NamePart
Specify the list of name parts.
.PARAMETER Name
Specify the name parts as a single name with forward slashes.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName
#>
function New-KerberosPrincipalName {
    [CmdletBinding(DefaultParameterSetName="FromName")]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosNameType]$Type,
        [Parameter(Mandatory, Position = 1, ParameterSetName = "FromName")]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName = "FromNamePart")]
        [string[]]$NamePart
    )


    switch($PSCmdlet.ParameterSetName) {
        "FromName" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]::new($Type, $Name)
        }
        "FromNamePart" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]::new($Type, $NamePart)
        }
    }
}

<#
.SYNOPSIS
Create a new Kerberos authenticator.
.DESCRIPTION
This cmdlet creates a new Kerberos authenticator. Note this doesn't encrypt it, it'll be in plain text.
.PARAMETER Checksum
Specify a Kerberos checksum.
.PARAMETER ClientRealm
Specify the realm for the client.
.PARAMETER ClientName
Specify the name for the client.
.PARAMETER SubKey
Specify a subkey.
.PARAMETER SequenceNumber
Specify a sequence number.
.PARAMETER AuthorizationData
Specify authorization data.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticator
#>
function New-KerberosAuthenticator {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$ClientRealm,
        [Parameter(Mandatory, Position = 1)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$ClientName,
        [datetime]$ClientTime = [datetime]::MinValue,
        [int]$ClientUSec = 0,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosChecksum]$Checksum,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$SubKey,
        [System.Nullable[int]]$SequenceNumber = $null,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthorizationData[]]$AuthorizationData
    )

    if ($ClientTime -eq [datetime]::MinValue) {
        $ClientTime = [datetime]::Now
    }
    [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticator]::Create($ClientRealm, $ClientName, $ClientTime, `
            $ClientUSec, $Checksum, $SubKey, $SequenceNumber, $AuthorizationData)
}

<#
.SYNOPSIS
Create a new Kerberos AP-REQ token.
.DESCRIPTION
This cmdlet creates a new Kerberos AP-REQ token.
.PARAMETER Ticket
Specify a Kerberos ticket.
.PARAMETER Authenticator
Specify the authenticator.
.PARAMETER AuthenticatorKey
Specify the key to encrypt the authenticator.
.PARAMETER AuthenticatorKeyVersion
Specify the key version to encrypt the authenticator.
.PARAMETER TicketKey
Specify the key to encrypt the ticket.
.PARAMETER AuthenticatorKeyVersion
Specify the key version to encrypt the ticket.
.PARAMETER RawToken
Specify to return a raw token with no GSSAPI header.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAPRequestAuthenticationToken
#>
function New-KerberosApRequest {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicket]$Ticket,
        [Parameter(Mandatory, Position = 1)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosEncryptedData]$Authenticator,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAPRequestOptions]$Options = 0,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$AuthenticatorKey,
        [System.Nullable[int]]$AuthenticatorKeyVersion,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$TicketKey,
        [System.Nullable[int]]$TicketKeyVersion,
        [switch]$RawToken
    )

    [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAPRequestAuthenticationToken]::Create($Ticket, $Authenticator, $Options, `
                $AuthenticatorKey, $AuthenticatorKeyVersion, $TicketKey, $TicketKeyVersion, $RawToken)
}

<#
.SYNOPSIS
Create a new Kerberos  ticket.
.DESCRIPTION
This cmdlet creates a new Kerberos ticket.
.PARAMETER Realm
Specify the ticket realm.
.PARAMETER ServerName
Specify the server name.
.PARAMETER EncryptedData
Specify the ticket encrypted data.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicket
#>
function New-KerberosTicket {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Realm,
        [Parameter(Mandatory, Position = 1)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$ServerName,
        [Parameter(Mandatory, Position = 2)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosEncryptedData]$EncryptedData
    )

    [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicket]::Create($Realm, $ServerName, $EncryptedData)
}

<#
.SYNOPSIS
Add a kerberos ticket to the cache.
.DESCRIPTION
This cmdlet adds an existing kerberos ticket to the system cache.
.PARAMETER Credential
Specify the ticket credential.
.PARAMETER Key
Specify the ticket credential key if needed.
.PARAMETER LogonId
Specify the logon ID for the ticket cache.
.PARAMETER Cache
Specify a local cache to add the ticket to.
.INPUTS
None
.OUTPUTS
None
#>
function Add-KerberosTicket {
    [CmdletBinding(DefaultParameterSetName="FromSystem")]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosCredential]$Credential,
        [Parameter(ParameterSetName="FromSystem")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$Key,
        [Parameter(ParameterSetName="FromSystem")]
        [NtCoreLib.Luid]$LogonId = 0,
        [Parameter(ParameterSetName="FromLocalCache", Mandatory)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]$Cache
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromSystem" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::SubmitTicket($Credential, $LogonId, $Key)
        }
        "FromLocalCache" {
            $Cache.AddTicket($Credential)
        }
    }
}

<#
.SYNOPSIS
Remove a kerberos ticket from the cache.
.DESCRIPTION
This cmdlet removes a kerberos ticket from the user's ticket cache.
.PARAMETER Realm
Specify the ticket realm.
.PARAMETER ServerName
Specify the server name.
.PARAMETER LogonId
Specify the logon ID for the ticket cache.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-KerberosTicket {
    [CmdletBinding(DefaultParameterSetName="FromName")]
    Param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromName")]
        [string]$Realm,
        [Parameter(Mandatory, Position = 1, ParameterSetName="FromName")]
        [string]$ServerName,
        [Parameter(Position = 2, ParameterSetName="FromName")]
        [NtCoreLib.Luid]$LogonId = 0,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromAll")]
        [switch]$All
    )

    [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::PurgeTicketCache($LogonId, $ServerName, $Realm)
}

<#
.SYNOPSIS
Create a new local Kerberos cache.
.DESCRIPTION
This cmdlet creates a new local Kerberos ticket cache. Defaults to populating from the current system cache.
.PARAMETER CreateClient
Create a client when initializing from the system cache or a list of tickets.
.PARAMETER LogonId
Specify the logon ID for the system cache to use.
.PARAMETER Hostname
Specify the hostname of the KDC to use for the cache.
.PARAMETER Port
Specify the port number of the KDC to use for the cache.
.PARAMETER Credential
Specify the TGT credentials to use for the cache.
.PARAMETER Realm
Specify the realm to use for the cache.
.PARAMETER AdditionalTicket
Specify additional tickets to add to the new cache.
.PARAMETER Key
Specify the user key to authenticate the new ticket cache.
.PARAMETER Request
Specify an AS-REQ to authentication the user for the new ticket cache.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache
#>
function New-KerberosTicketCache {
    [CmdletBinding(DefaultParameterSetName="FromSystem")]
    Param(
        [Parameter(ParameterSetName="FromSystem")]
        [Parameter(ParameterSetName="FromTickets")]
        [switch]$CreateClient,
        [Parameter(ParameterSetName="FromSystem")]
        [NtCoreLib.Luid]$LogonId = 0,
        [Parameter(ParameterSetName="FromTgt", Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosCredential]$Credential,
        [Parameter(ParameterSetName="FromKey", Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$Key,
        [Parameter(ParameterSetName="FromRequest", Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosASRequestBase]$Request,
        [Parameter(ParameterSetName="FromTgt")]
        [Parameter(ParameterSetName="FromKey")]
        [string]$Hostname,
        [Parameter(ParameterSetName="FromTgt")]
        [Parameter(ParameterSetName="FromKey")]
        [int]$Port = 88,
        [Parameter(ParameterSetName="FromTgt")]
        [string]$Realm = [NullString]::Value,
        [Parameter(ParameterSetName="FromTgt")]
        [Parameter(Mandatory, ParameterSetName="FromTickets")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosExternalTicket[]]$AdditionalTicket
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromSystem" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]::FromSystemCache($CreateClient, $LogonId)
        }
        "FromTgt" {
            $client = [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosKDCClient]::CreateTCPClient($Hostname, $Port)
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]::new($Credential, $client, $Realm, $AdditionalTicket)
        }
        "FromKey" {
            $client = [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosKDCClient]::CreateTCPClient($Hostname, $Port)
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]::FromClient($client, $Key)
        }
        "FromRequest" {
            $client = [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosKDCClient]::CreateTCPClient($Hostname, $Port)
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]::FromClient($client, $Request)
        }
        "FromTickets" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]::FromTickets($AdditionalTicket, $CreateClient)
        }
    }
}

<#
.SYNOPSIS
Import a Kerberos ticket cache from a file.
.DESCRIPTION
This cmdlet imports a Kerberos ticket cache from an MIT style ccache file.
.PARAMETER Path
Specify the path to import.
.PARAMETER CreateClient
Specify to create a KDC client.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache
#>
function Import-KerberosTicketCache {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Path,
        [switch]$CreateClient
    )

    $Path = Resolve-Path $Path
    if ($null -ne $Path) {
        [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]::FromFile($Path, $CreateClient)
    }
}

<#
.SYNOPSIS
Export a Kerberos ticket cache to a file.
.DESCRIPTION
This cmdlet exports a Kerberos ticket cache to an MIT style ccache file.
.PARAMETER Cache
Specify the cache to export.
.PARAMETER Path
Specify the path to export to.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache
#>
function Export-KerberosTicketCache {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]$Cache,
        [Parameter(Mandatory, Position = 1)]
        [string]$Path
    )

    $cache_bytes = $cache.ToCredentialFile().Export($Path)
    Write-BinaryFile -Path $Path -Byte $cache_bytes
}

<#
.SYNOPSIS
Rename the kerberos ticket's server name.
.DESCRIPTION
This cmdlet renames the server name of a Kerberos ticket.
.PARAMETER Ticket
Specify the ticket to rename.
.PARAMETER Name
Specify the principal name
.PARAMETER ServiceName
Specify a service name of type SRV_INST.
.PARAMETER Realm
Specify the realm
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicket
#>
function Rename-KerberosTicket {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicket]$Ticket,
        [Parameter(Mandatory, Position = 1)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$Name,
        [string]$Realm
    )

    if ("" -eq $Realm) {
        $Realm = $Ticket.Realm
    }

    [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicket]::Create($Realm, $Name, $Ticket.EncryptedData)
}

<#
.SYNOPSIS
Creates a new Kerberos error.
.DESCRIPTION
This cmdlet creates a new Kerberos error authentication token.
.PARAMETER ErrorCode
Specify error code.
.PARAMETER ServerName
Specify the server principal name
.PARAMETER ServerRealm
Specify the server realm.
.PARAMETER ServerTime
Specify the server time.
.PARAMETER ServerUsec
Specify the server usecs.
.PARAMETER ClientName
Specify the client principal name.
.PARAMETER ClientRealm
Specify the client realm.
.PARAMETER ClientTime
Specify the client time.
.PARAMETER ClientUsec
Specify the client usecs.
.PARAMETER ErrorText
Specify the error text.
.PARAMETER ErrorData
Specify the error data.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosErrorAuthenticationToken
#>
function New-KerberosError {
    [CmdletBinding(DefaultParameterSetName="FromBytes")]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosErrorType]$ErrorCode,
        [Parameter(Mandatory, Position = 1)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$ServerName,
        [Parameter(Mandatory, Position = 2)]
        [string]$ServerRealm,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTime]$ServerTime,
        [int]$ServerUsec = 0,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$ClientName,
        [string]$ClientRealm,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTime]$ClientTime,
        [System.Nullable[int]]$ClientUsec,
        [string]$ErrorText,
        [Parameter(ParameterSetName="FromBytes")]
        [byte[]]$ErrorData,
        [Parameter(Mandatory, Position = 3, ParameterSetName="FromErrorData")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosErrorData]$ErrorDataValue,
        [switch]$NoWrapper
    )

    if ($ServerTime -eq $null) {
        $ServerTime = [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTime]::Now
    }

    if ($PSCmdlet.ParameterSetName -eq "FromErrorData") {
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosErrorAuthenticationToken]::Create($ServerTime, $ServerUsec,
            $ErrorCode, $ServerRealm, $ServerName, $ErrorDataValue, $ClientTime, $ClientUsec, $ClientRealm, $ClientName, $ErrorText,
            $NoWrapper)
    } else {
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosErrorAuthenticationToken]::Create($ServerTime, $ServerUsec,
            $ErrorCode, $ServerRealm, $ServerName, $ClientTime, $ClientUsec, $ClientRealm, $ClientName, $ErrorText, $ErrorData,
            $NoWrapper)
    }
}

<#
.SYNOPSIS
Add a Kerberos KDC pin.
.DESCRIPTION
This cmdlet adds a Kerberos KDC pin to always call a specific KDC for a realm. Only applies the pin to the current thread.
.PARAMETER Realm
Specify the realm.
.PARAMETER Hostname
Specify the hostname of the KDC.
.INPUTS
None
.OUTPUTS
None
#>
function Add-KerberosKdcPin {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Realm,
        [Parameter(Mandatory, Position = 1)]
        [string]$Hostname
    )
    [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::PinKdc($Realm, $Hostname, 0)
}

<#
.SYNOPSIS
Clear all Kerberos KDC pins.
.DESCRIPTION
This cmdlet clears all Kerberos KDC pin for the current thread.
.INPUTS
None
.OUTPUTS
None
#>
function Clear-KerberosKdcPin {
    [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::UnpinAllKdcs()
}

<#
.SYNOPSIS
Create a new AS-REQ object.
.DESCRIPTION
This cmdlet creates a new AS-REQ object for sending to a KDC.
.PARAMETER Realm
Specify the realm.
.PARAMETER ClientName
Specify the client name for the ticket.
.PARAMETER ServerName
Specify the server name for the ticket.
.PARAMETER EncryptionType
Specify a list of encryption types for the requested ticket.
.PARAMETER Forwardable
Specify to request a forwardable ticket.
.PARAMETER Canonicalize
Specify to canonicalize names.
.PARAMETER Renewable
Specify to request a renewable ticket.
.PARAMETER Password
Specify the user's password.
.PARAMETER Certificate
Specify the user's certificate.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosASRequest
#>
function New-KerberosAsRequest {
    [CmdletBinding(DefaultParameterSetName="FromKey")]
    Param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromKey")]
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromKeyWithName")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$Key,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromPassword")]
        [NtObjectManager.Utils.PasswordHolder]$Password,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromCertificate")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory, Position = 1, ParameterSetName="FromKeyWithName")]
        [Parameter(Mandatory, Position = 1, ParameterSetName="FromPassword")]
        [Parameter(Position = 1, ParameterSetName="FromCertificate")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$ClientName,
        [Parameter(Mandatory, Position = 2, ParameterSetName="FromKeyWithName")]
        [Parameter(Mandatory, Position = 2, ParameterSetName="FromPassword")]
        [Parameter(Position = 2, ParameterSetName="FromCertificate")]
        [string]$Realm,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromCredential")]
        [NtCoreLib.Win32.Security.Authentication.UserCredentials]$Credential,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromReadCredential")]
        [switch]$ReadCredential,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$ServerName,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosEncryptionType[]]$EncryptionType,
        [switch]$Forwardable,
        [switch]$Canonicalize,
        [switch]$Renewable
    )

    $req = switch($PSCmdlet.ParameterSetName) {
        "FromKey" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosASRequest]::new($Key)
        }
        "FromKeyWithName" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosASRequest]::new($Key, $ClientName, $Realm)
        }
        "FromPassword" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosASRequestPassword]::new($Password.ToPlainText(), $ClientName, $Realm)
        }
        "FromCertificate" {
            if ($null -eq $ClientName -and "" -eq $Realm) {
                [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosASRequestCertificate]::new($Certificate)
            } else {
                [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosASRequestCertificate]::new($Certificate, $ClientName, $Realm)
            }
        }
        "FromCredential" {
            New-KerberosAsRequest -Password $Credential.Password -ClientName $Credential.UserName -Realm $Credential.Domain
        }
        "FromReadCredential" {
            $Credential = Read-LsaCredential
            New-KerberosAsRequest -Password $Credential.Password -ClientName $Credential.UserName -Realm $Credential.Domain
        }
    }

    if ($null -eq $req) {
        return
    }

    if ($null -ne $EncryptionType) {
        $req.EncryptionTypes.AddRange($EncryptionType)
    }

    $req.ServerName = $ServerName
    $req.Forwardable = $Forwardable
    $req.Canonicalize = $Canonicalize
    $req.Renewable = $Renewable
    $req
}

<#
.SYNOPSIS
Create a new TGS-REQ object.
.DESCRIPTION
This cmdlet creates a new TGS-REQ object for sending to a KDC.
.PARAMETER Realm
Specify the realm.
.PARAMETER ServerName
Specify the server name for the ticket.
.PARAMETER Credential
Specify the credentials for the TGS request. This could be a TGT or a service ticket for renewal.
.PARAMETER Renew
Specify to make the request renew the credential.
.PARAMETER EncryptionType
Specify a list of encryption types for the requested ticket.
.PARAMETER Forwardable
Specify to request a forwardable ticket.
.PARAMETER Canonicalize
Specify to canonicalize names.
.PARAMETER Renewable
Specify to request a renewable ticket.
.PARAMETER S4U2Proxy
Specify an existing S4U2Self ticket to create an S4U2Proxy ticket
.PARAMETER S4UUserName
Specify the user name for an S4U2Self ticket.
.PARAMETER EncryptTicketInSessionKey
Specify to encrypt the ticket using the session key from another ticket.
.PARAMETER AdditionalTicket
Specify additional tickets. Typically used with EncryptTicketInSessionKey.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosTGSRequest
#>
function New-KerberosTgsRequest {
    [CmdletBinding(DefaultParameterSetName="Create")]
    Param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="Create")]
        [Parameter(Mandatory, Position = 0, ParameterSetName="Renew")]
        [Parameter(Mandatory, Position = 0, ParameterSetName="S4U2Self")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosCredential]$Credential,
        [Parameter(Mandatory, Position = 1, ParameterSetName="Create")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$ServerName,
        [Parameter(Mandatory, Position = 2, ParameterSetName="Create")]
        [Parameter(Mandatory, ParameterSetName="S4U2Self")]
        [string]$Realm,
        [Parameter(ParameterSetName="Create")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicket]$S4U2Proxy,
        [Parameter(Mandatory, ParameterSetName="Renew")]
        [switch]$Renew,
        [Parameter(Mandatory, ParameterSetName="S4U2Self")]
        [string]$S4UUserName,
        [switch]$EncryptTicketInSessionKey,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosEncryptionType[]]$EncryptionType,
        [switch]$Forwardable,
        [switch]$Canonicalize,
        [switch]$Renewable,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicket[]]$AdditionalTicket
    )

    $tgs = switch($PSCmdlet.ParameterSetName) {
        "Create" {
            if ($S4U2Proxy -eq $null) {
                [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosTGSRequest]::Create($Credential, $ServerName, $Realm)
            } else {
                [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosTGSRequest]::CreateForS4U2Proxy($Credential, $ServerName, $Realm, $S4U2Proxy)
            }
        }
        "Renew" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosTGSRequest]::CreateForRenewal($Credential)
        }
        "S4U2Self" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosTGSRequest]::CreateForS4U2Self($Credential, $S4UUserName, $Realm, $EncryptTicketInSessionKey)
        }
    }

    if ($null -ne $EncryptionType) {
        $tgs.EncryptionTypes.AddRange($EncryptionType)
    }
    if ($null -ne $AdditionalTicket) {
        foreach($t in $AdditionalTicket) {
            $tgs.AddAdditionalTicket($t)
        }
    }
    $tgs.Forwardable = $Forwardable
    $tgs.Canonicalize = $Canonicalize
    $tgs.Renewable = $Renewable
    $tgs.EncryptTicketInSessionKey = $EncryptTicketInSessionKey
    $tgs
}

<#
.SYNOPSIS
Send a Kerberos KDC request.
.DESCRIPTION
This cmdlet sends a request on the KDC for a KDC-REQ object.
.PARAMETER Hostname
Specify the hostname of the KDC.
.PARAMETER Port
Specify the port of the KDC.
.PARAMETER Request
Specify the request to send.
.PARAMETER AsExternalTicket
Specify to return as an KerberosExternalTicket
.PARAMETER AsKdcReply
Specify to return the raw reply.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosCredential
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosExternalTicket
NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosKdcReply
#>
function Send-KerberosKdcRequest {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosKDCRequest]$Request,
        [string]$Hostname,
        [int]$Port = 88,
        [switch]$AsExternalTicket,
        [switch]$AsKdcReply
    )
    $client = [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosKDCClient]::CreateTCPClient($Hostname, $Port)
    $reply = if ($Request -is [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosTGSRequest]) {
        $client.RequestServiceTicket($Request)
    } elseif ($Request -is [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosASRequestBase]) {
        $client.Authenticate($Request)
    } else {
        throw "Unknown KDC request type."
    }
    if ($null -ne $reply) {
        if($AsKdcReply) {
            $reply
        } elseif ($AsExternalTicket) {
            $reply.ToExternalTicket()
        } else {
            $reply.ToCredential()
        }
    }
}

<#
.SYNOPSIS
Create a new test Kerberos KDC server.
.DESCRIPTION
This cmdlet configures and creates a new KDC test server. You should call Start on the returned server when you want to use it.
.PARAMETER Realm
Specify the KDC's default realm.
.PARAMETER DomainSid
Specify the KDC's domain SID.
.PARAMETER Address
Specify the address to listen on.
.PARAMETER Port
Specify the TCP port to listen on.
.PARAMETER User
Specify the users hosted by the KDC.
.PARAMETER AdditionalKey
Specify additional service keys.
.PARAMETER KrbTgtKey
Specify optional krbtgt key.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.Server.KerberosKDCServer
#>
function New-KerberosKdcServer {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Realm,
        [NtCoreLib.Security.Authorization.Sid]$DomainSid,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.Server.KerberosKDCServerUser[]]$User,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey[]]$AdditionalKey,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$KrbTgtKey,
        [ipaddress]$Address = [ipaddress]::Loopback,
        [int]$Port = 88
    )

    $config = [NtCoreLib.Win32.Security.Authentication.Kerberos.Server.KerberosKDCServerConfig]::new()
    $config.Realm = $Realm
    $config.DomainSid = $DomainSid
    $config.Listener = [NtCoreLib.Win32.Security.Authentication.Kerberos.Server.KerberosKDCServerListenerTCP]::new($Address, $Port)
    if ($User -ne $null) {
        $config.Users.AddRange($User)
    }
    if ($AdditionalKey -ne $null) {
        $config.AdditionalKeys.AddRange($AdditionalKey)
    }
    $config.KrbTgtKey = $KrbTgtKey
    $config.Create()
}

<#
.SYNOPSIS
Create a new test Kerberos KDC user.
.DESCRIPTION
This cmdlet configures and creates a new KDC user.
.PARAMETER Username
Specify the user's name.
.PARAMETER UserId
Specify the user's domain RID.
.PARAMETER Key
Specify the user's keys.
.PARAMETER GroupId
Specify the user's group IDs.
.PARAMETER PrimaryGroupId
Specify the user's primary group ID.
.PARAMETER ServicePrincipalName
Specify the user's service principal names.
.PARAMETER ExtraSid
Specify the user's extra SIDs.
.PARAMETER AuthorizationData
Specify the user's authorization data.
.PARAMETER ResourceGroupDomainSid
Specify the user's resource group domain SID.
.PARAMETER ResourceGroupId
Specify the user's resource group IDs.
.PARAMETER UserAccountControlFlag
Specify the user's account control flags.
.PARAMETER
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.Server.KerberosKDCServerUser
#>
function New-KerberosKdcServerUser {
    [CmdletBinding(DefaultParameterSetName="FromPassword")]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Username,
        [Parameter(Mandatory, Position = 1)]
        [uint32]$UserId,
        [Parameter(Mandatory, Position = 2, ParameterSetName="FromPassword")]
        [AllowEmptyString()]
        [string]$Password,
        [Parameter(Mandatory, Position = 2, ParameterSetName="FromKeys")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey[]]$Key,
        [NtCoreLib.Security.Authorization.Sid]$DomainSid,
        [uint32[]]$GroupId,
        [uint32]$PrimaryGroupId = 513,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName[]]$ServicePrincipalName,
        [NtCoreLib.Security.Authorization.Sid[]]$ExtraSid,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthorizationData[]]$AuthorizationData,
        [NtCoreLib.Security.Authorization.Sid]$ResourceGroupDomainSid,
        [uint32[]]$ResourceGroupId,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.UserAccountControlFlags]$UserAccountControlFlag = "NormalAccount"
    )
    $user = [NtCoreLib.Win32.Security.Authentication.Kerberos.Server.KerberosKDCServerUser]::new($username)
    $user.UserId = $UserId
    switch($PSCmdlet.ParameterSetName) {
        "FromPassword" {
            $user.Password = $Password
        }
        "FromKeys" {
            $user.Keys.AddRange($Key)
        }
    }
    $user.DomainSid = $DomainSid
    foreach($rid in $GroupId) {
        $user.AddGroupId($rid)
    }
    $user.PrimaryGroupId = $PrimaryGroupId
    foreach($spn in $ServicePrincipalName) {
        $user.ServicePrincipalNames.Add($spn) | Out-Null
    }
    foreach ($sid in $ExtraSid) {
        $attr = "Mandatory, Enabled, EnabledByDefault"
        if (Test-NtSid $sid -Integrity) {
            $attr = "Integrity, IntegrityEnabled"
        }
        $user.AddExtraSid($sid, $attr)
    }
    if ($AuthorizationData -ne $null) {
        $user.AuthorizationData.AddRange($AuthorizationData)
    }
    if ($ResourceGroupDomainSid -ne $null -and $ResourceGroupId -ne $null) {
        $user.ResourceGroupDomainSid = $ResourceGroupDomainSid
        foreach($rid in $ResourceGroupId) {
            $user.AddResourceGroupId($rid)
        }
    }
    $user.UserAccountControlFlags = $UserAccountControlFlag
    $user
}

<#
.SYNOPSIS
Create a new Kerberos authorization data value.
.DESCRIPTION
This cmdlet a new Kerberos authorization data value.
.PARAMETER SecurityContext
Specify to create a KERB-LOCAL  authorization data.
.PARAMETER AuthorizationData
Specify to create a AD-IF-RELEVANT authorization data.
.PARAMETER RestrictionFlag
Specify the flags for a KERB-AD-RESTRICTION-ENTRY authorization data.
.PARAMETER IntegrityLevel
Specify the integrity level for a KERB-AD-RESTRICTION-ENTRY authorization data.
.PARAMETER MachineId
Specify the machine ID for a KERB-AD-RESTRICTION-ENTRY authorization data.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthorizationData
#>
function New-KerberosAuthorizationData {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="IfRelevant")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthorizationData[]]$AuthorizationData,
        [Parameter(Mandatory, ParameterSetName="KerbLocal")]
        [byte[]]$SecurityContext,
        [Parameter(Mandatory, ParameterSetName="KerbRest")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosRestrictionEntryFlags]$RestrictionFlag,
        [Parameter(Mandatory, ParameterSetName="KerbRest")]
        [NtCoreLib.TokenIntegrityLevel]$IntegrityLevel,
        [Parameter(Mandatory, ParameterSetName="KerbRest")]
        [byte[]]$MachineId
    )
    switch($PSCmdlet.ParameterSetName) {
        "IfRelevant" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthorizationDataIfRelevant]::new($AuthorizationData)
        }
        "KerbLocal" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthorizationDataKerbLocal]::new($SecurityContext)
        }
        "KerbRest" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthorizationDataRestrictionEntry]::new($RestrictionFlag, $IntegrityLevel, $MachineId)
        }
    }
}

<#
.SYNOPSIS
Tries to resolve a list of KDC services for a realm.
.DESCRIPTION
This cmdlet uses DNS to query the list of KDC services for a realm.
.PARAMETER Realm
Specify the realm to query for.
.PARAMETER DnsServerAddress
Specify the address of the DNS server.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Dns.DnsServiceRecord[]
#>
function Resolve-KerberosKdcAddress {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position=0)]
        [string]$Realm,
        [System.Net.IPAddress]$DnsServerAddress
    )

    [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosKDCClient]::QueryKdcForRealm($Realm, $DnsServerAddress) | Write-Output
}

<#
.SYNOPSIS
Export a Kerberos ticket/credential.
.DESCRIPTION
This cmdlet exports a kerberos ticket/credential to a file or bytes.
.PARAMETER Credential
Specify the Kerberos credential.
.PARAMETER Path
Specify the path.
.PARAMETER Base64
Specify to export as base64.
.PARAMETER InsertLineBreaks
Specify to insert line breaks in the base64.
.PARAMETER Key
Specify a key to encrypt the credential.
.INPUTS
None
.OUTPUTS
string
#>
function Export-KerberosTicket {
    [CmdletBinding(DefaultParameterSetName="ToFile")]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosCredential]$Credential,
        [Parameter(Mandatory, Position = 1, ParameterSetName="ToFile")]
        [string]$Path,
        [Parameter(Mandatory, ParameterSetName="ToBase64")]
        [switch]$Base64,
        [Parameter(ParameterSetName="ToBase64")]
        [switch]$InsertLineBreaks,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$Key
    )

    if ($null -ne $Key) {
        $Credential = $Credential.Encrypt($Key)
    }
    $ba = $Credential.ToArray()

    if ($PSCmdlet.ParameterSetName -eq "ToFile") {
        Write-BinaryFile -Path $Path -Byte $ba
    } else {
        $flags = if ($InsertLineBreaks) {
            [System.Base64FormattingOptions]::InsertLineBreaks
        } else {
            [System.Base64FormattingOptions]::None
        }
        [Convert]::ToBase64String($ba, $flags)
    }
}

<#
.SYNOPSIS
Import a Kerberos ticket/credential.
.DESCRIPTION
This cmdlet imports a kerberos ticket/credential from a file or bytes.
.PARAMETER Credential
Specify the Kerberos credential.
.PARAMETER Path
Specify the path.
.PARAMETER Base64
Specify to export as base64.
.PARAMETER Key
Specify a key to decrypt the credential.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosCredential
#>
function Import-KerberosTicket {
    [CmdletBinding(DefaultParameterSetName="FromFile")]
    Param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromFile")]
        [string]$Path,
        [Parameter(Mandatory, ParameterSetName="FromBase64")]
        [string]$Base64,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$Key
    )

    $ba = if ($PSCmdlet.ParameterSetName -eq "FromFile") {
        Read-BinaryFile -Path $Path
    } else {
        [Convert]::FromBase64String($Base64)
    }

    if ($null -eq $ba) {
        return
    }

    $cred = [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosCredential]::Parse($ba)
    if ($null -eq $cred) {
        return
    }
    
    if ($Key -ne $null) {
        $cred.Decrypt($Key)
    } else {
        $cred
    }
}

<#
.SYNOPSIS
Get current authentication packages.
.DESCRIPTION
This cmdlet gets the list of current authentication packages.
.PARAMETER Name
The name of the authentication package.
.PARAMETER Managed
Specify to get a managed authentication package.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.AuthenticationPackage
.EXAMPLE
Get-LsaPackage
Get all authentication packages.
.EXAMPLE
Get-LsaPackage -Name NTLM
Get the NTLM authentication package.
#>
function Get-LsaPackage {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromName")]
        [string]$Name,
        [Parameter(ParameterSetName = "FromName")]
        [switch]$Managed
    )

    switch ($PSCmdlet.ParameterSetName) {
        "All" {
            [NtCoreLib.Win32.Security.Authentication.AuthenticationPackage]::Get() | Write-Output
        }
        "FromName" {
            [NtCoreLib.Win32.Security.Authentication.AuthenticationPackage]::FromName($Name, $Managed) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Read's user credentials from the shell.
.DESCRIPTION
This cmdlet reads the user credentials from the shell and encodes the password.
.PARAMETER UserName
The username to use.
.PARAMETER Domain
The domain to use.
.PARAMETER Password
The password to use.
.PARAMETER AsNtHashCred
Specify to convert the user credential to an NT hash credential.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.UserCredentials
.EXAMPLE
$user_creds = Read-LsaCredential
Read user credentials from the shell.
#>
function Read-LsaCredential {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0)]
        [string]$UserName,
        [Parameter(Position = 1)]
        [string]$Domain,
        [Parameter(Position = 2)]
        [NtObjectManager.Utils.PasswordHolder]$Password,
        [switch]$AsNtHashCred
    )

    $creds = [NtCoreLib.Win32.Security.Authentication.UserCredentials]::new()
    if ($UserName -eq "") {
        $UserName = Read-Host -Prompt "UserName"
    }
    $creds.UserName = $UserName
    if ($Domain -eq "") {
        $Domain = Read-Host -Prompt "Domain"
    }
    $creds.Domain = $Domain
    if ($null -ne $Password) {
        $creds.Password = $Password.Password
    }
    else {
        $creds.Password = Read-Host -AsSecureString -Prompt "Password"
    }
    if ($AsNtHashCred) {
        [NtCoreLib.Win32.Security.Authentication.Ntlm.Client.NtHashAuthenticationCredentials]::new($creds)
    } else {
        $creds
    }
}

<#
.SYNOPSIS
Get user credentials.
.DESCRIPTION
This cmdlet gets user credentials.
.PARAMETER UserName
The username to use.
.PARAMETER Domain
The domain to use.
.PARAMETER Password
The password to use, can be a string or a StringString.
.PARAMETER Cache
A local Kerberos cache to use for Kerberos authentication.
.PARAMETER SessionKeyTicket
A ticket to use for the session key in Kerberos authentication.
.PARAMETER Ticket
A Kerberos ticket to use.
.PARAMETER AsNtHashCred
Specify to convert the user credential to an NT hash credential.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.AuthenticationCredentials
.EXAMPLE
$user_creds = Get-LsaCredential -UserName "ABC" -Domain "DOMAIN" -Password "pwd"
Get user credentials from components.
#>
function Get-LsaCredential {
    [CmdletBinding(DefaultParameterSetName="FromCreds")]
    Param(
        [Parameter(Position = 0, ParameterSetName="FromCreds")]
        [string]$UserName,
        [Parameter(Position = 1, ParameterSetName="FromCreds")]
        [string]$Domain,
        [Parameter(Position = 2, ParameterSetName="FromCreds")]
        [alias("SecurePassword")]
        [NtObjectManager.Utils.PasswordHolder]$Password,
        [Parameter(ParameterSetName="FromCreds")]
        [switch]$AsNtHashCred,
        [Parameter(ParameterSetName="FromLocalCache", Mandatory)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]$Cache,
        [Parameter(ParameterSetName="FromLocalCache")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicket]$SessionKeyTicket,
        [Parameter(ParameterSetName="FromTicket", Mandatory)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosExternalTicket]$Ticket
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromCreds" {
            $creds = [NtCoreLib.Win32.Security.Authentication.UserCredentials]::new()
            if ($UserName -ne "") {
                $creds.UserName = $UserName
            }
    
            if ($Domain -ne "") {
                $creds.Domain = $Domain
            }

            if ($null -ne $Password) {
                $creds.Password = $Password.Password
            }
            if ($AsNtHashCred) {
                [NtCoreLib.Win32.Security.Authentication.Ntlm.Client.NtHashAuthenticationCredentials]::new($creds)
            } else {
                $creds
            }
        }
        "FromLocalCache" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosTicketCacheAuthenticationCredentials]::new($Cache, $SessionKeyTicket)
        }
        "FromTicket" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosTicketAuthenticationCredentials]::new($Ticket)
        }
    }
}

<#
.SYNOPSIS
Get Schannel credentials.
.DESCRIPTION
This cmdlet gets Schannel credentials.
.PARAMETER Flags
The flags for the credentials.
.PARAMETER SessionLifespan
The lifespan of a session in milliseconds.
.PARAMETER Certificate
The list of certificates to use. Needs to have a private key.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Schannel.SchannelCredentials
.EXAMPLE
$creds = Get-LsaSchannelCredential -Certificate $cert
Get credentials with a certificate.
#>
function Get-LsaSchannelCredential {
    [CmdletBinding()]
    Param(
        [NtCoreLib.Win32.Security.Authentication.Schannel.SchannelCredentialsFlags]$Flags = 0,
        [int]$SessionLifespan = 0,
        [X509Certificate[]]$Certificate
    )

    $creds = [NtCoreLib.Win32.Security.Authentication.Schannel.SchannelCredentials]::new()
    $creds.Flags = $Flags
    $creds.SessionLifespan = $SessionLifespan
    foreach($cert in $Certificate) {
        $creds.AddCertificate($cert)
    }
    $creds
}

<#
.SYNOPSIS
Get CredSSP credentials.
.DESCRIPTION
This cmdlet gets CredSSP credentials. This is only needed if you want both Schannel and user credentials. Otherwise
just use Get-LsaSchannelCredential or Get-LsaCredential.
.PARAMETER Schannel
The Schannel credentials.
.PARAMETER User
The user credentials.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.CredSSP.CredSSPCredentials
.EXAMPLE
$creds = Get-LsaCredSSPCredential -Schannel $schannel -User $user
Get credentials from a schannel and user credentials object.
#>
function Get-LsaCredSSPCredential {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position=0)]
        [NtCoreLib.Win32.Security.Authentication.Schannel.SchannelCredentials]$Schannel,
        [Parameter(Mandatory, Position=1)]
        [NtCoreLib.Win32.Security.Authentication.UserCredentials]$User
    )

    [NtCoreLib.Win32.Security.Authentication.CredSSP.CredSSPCredentials]::new($Schannel, $User)
}

<#
.SYNOPSIS
Create a new credentials handle.
.DESCRIPTION
This cmdlet creates a new authentication credentials handle.
.PARAMETER Package
The name of the package to use.
.PARAMETER UseFlag
The use flags for the credentials.
.PARAMETER AuthId
Optional authentication ID to authenticate.
.PARAMETER Principal
Optional principal to authentication.
.PARAMETER Credential
Optional Credentials for the authentication.
.PARAMETER ReadCredential
Specify to read the credentials from the console if not specified explicitly.
.PARAMETER UserName
The username to use.
.PARAMETER Domain
The domain to use.
.PARAMETER Password
The password to use.
.PARAMETER Managed
Specify to create a managed credential handle.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.ICredentialHandle
.EXAMPLE
$h = New-LsaCredentialHandle -Package "NTLM" -UseFlag Both
Get a credential handle for the NTLM package for both directions.
.EXAMPLE
$h = New-LsaCredentialHandle -Package "NTLM" -UseFlag Both -UserName "user" -Password "pwd"
Get a credential handle for the NTLM package for both directions with a username password.
.EXAMPLE
$h = New-LsaCredentialHandle -Package "NTLM" -UseFlag Inbound -ReadCredential
Get a credential handle for the NTLM package for outbound directions and read credentials from the shell.
#>
function New-LsaCredentialHandle {
    [CmdletBinding(DefaultParameterSetName="FromCreds")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Package,
        [Parameter(Position = 1, Mandatory)]
        [NtCoreLib.Win32.Security.Authentication.SecPkgCredFlags]$UseFlag,
        [Nullable[NtCoreLib.Luid]]$AuthId,
        [string]$Principal,
        [Parameter(ParameterSetName="FromCreds")]
        [NtCoreLib.Win32.Security.Authentication.AuthenticationCredentials]$Credential,
        [Parameter(ParameterSetName="FromParts")]
        [switch]$ReadCredential,
        [Parameter(ParameterSetName="FromParts")]
        [string]$UserName,
        [Parameter(ParameterSetName="FromParts")]
        [string]$Domain,
        [Parameter(ParameterSetName="FromParts")]
        [alias("SecurePassword")]
        [NtObjectManager.Utils.PasswordHolder]$Password,
        [switch]$Managed
    )

    if ($PSCmdlet.ParameterSetName -eq "FromParts") {
        if ($ReadCredential) {
            $Credential = Read-LsaCredential -UserName $UserName -Domain $Domain `
                    -Password $Password
        } else {
            $Credential = Get-LsaCredential -UserName $UserName -Domain $Domain `
                    -Password $Password
        }
    }

    $pkg = Get-LsaPackage -Name $Package -Managed:$Managed
    if ($null -ne $pkg) {
        $pkg.CreateHandle($UseFlag, $Credential, $Principal, $AuthId)
    }
}

$package_completer = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    (Get-LsaPackage).Name | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object { "'$_'" }
}

Register-ArgumentCompleter -CommandName New-LsaCredentialHandle -ParameterName Package -ScriptBlock $package_completer

<#
.SYNOPSIS
Create a new authentication client.
.DESCRIPTION
This cmdlet creates a new authentication client.
.PARAMETER CredHandle
The credential handle to use.
.PARAMETER RequestAttribute
Request attributes.
.PARAMETER Target
Optional SPN target.
.PARAMETER DataRepresentation
Data representation format.
.PARAMETER ChannelBinding
Optional channel binding token.
.PARAMETER NoInit
Don't initialize the client authentication context.
.PARAMETER Cache
Specify a local kerberos ticket cache.
.PARAMETER CacheOnly
Only use cached Kerberos tickets.
.PARAMETER SubKeyEncryptionType
Specify the type of sub-key encryption to use.
.PARAMETER SubKey
Specify a specify key to use for the authenticator subkey.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.ClientAuthenticationContext
#>
function New-LsaClientContext {
    [CmdletBinding(DefaultParameterSetName="FromCredHandle")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromCredHandle")]
        [NtCoreLib.Win32.Security.Authentication.ICredentialHandle]$CredHandle,
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromTicketCache")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]$Cache,
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromTicket")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosExternalTicket]$Ticket,
        [NtCoreLib.Win32.Security.Authentication.InitializeContextReqFlags]$RequestAttribute = 0,
        [Parameter(ParameterSetName="FromCredHandle")]
        [Parameter(Mandatory, ParameterSetName="FromTicketCache")]
        [string]$Target,
        [NtObjectManager.Utils.ChannelBindingHolder]$ChannelBinding,
        [Parameter(ParameterSetName="FromCredHandle")]
        [NtCoreLib.Win32.Security.Authentication.SecDataRep]$DataRepresentation = "Native",
        [Parameter(ParameterSetName="FromCredHandle")]
        [switch]$NoInit,
        [Parameter(ParameterSetName="FromTicketCache")]
        [Parameter(ParameterSetName="FromTicket")]
        [System.Nullable[NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosEncryptionType]]$SubKeyEncryptionType,
        [Parameter(ParameterSetName="FromTicketCache")]
        [Parameter(ParameterSetName="FromTicket")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$SubKey,
        [Parameter(ParameterSetName="FromTicketCache")]
        [switch]$CacheOnly,
        [Parameter(ParameterSetName="FromTicketCache")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicket]$SessionKeyTicket,
        [Parameter(ParameterSetName="FromTicketCache")]
        [switch]$S4U2Self
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromCredHandle" {
            $CredHandle.CreateClient($RequestAttribute, $Target, $ChannelBinding, $DataRepresentation, !$NoInit)
        }
        "FromTicketCache" {
            $config = [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosClientAuthenticationContextConfig]::new()
            $config.SubKeyEncryptionType = $SubKeyEncryptionType
            $config.SubKey = $SubKey
            $config.ChannelBinding = $ChannelBinding
            $config.SessionKeyTicket = $SessionKeyTicket
            $config.S4U2Self = $S4U2Self
            $Cache.CreateClientContext($Target, $RequestAttribute, $CacheOnly, $config)
        }
        "FromTicket" {
            $config = [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosClientAuthenticationContextConfig]::new()
            $config.SubKeyEncryptionType = $SubKeyEncryptionType
            $config.SubKey = $SubKey
            $config.ChannelBinding = $ChannelBinding
            $config.Create($Ticket, $RequestAttribute)
        }
    }
}

<#
.SYNOPSIS
Create a new authentication server.
.DESCRIPTION
This cmdlet creates a new authentication server.
.PARAMETER CredHandle
The credential handle to use.
.PARAMETER RequestAttribute
Request attributes.
.PARAMETER DataRepresentation
Data representation format.
.PARAMETER ChannelBinding
Optional channel binding token.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.ServerAuthenticationContext
#>
function New-LsaServerContext {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Win32.Security.Authentication.ICredentialHandle]$CredHandle,
        [NtCoreLib.Win32.Security.Authentication.AcceptContextReqFlags]$RequestAttribute = 0,
        [NtCoreLib.Win32.Security.Authentication.SecDataRep]$DataRepresentation = "Native",
        [NtObjectManager.Utils.ChannelBindingHolder]$ChannelBinding
    )

    $CredHandle.CreateServer($RequestAttribute, $ChannelBinding, $DataRepresentation)
}

<#
.SYNOPSIS
Update an authentication client.
.DESCRIPTION
This cmdlet updates an authentication client. Returns true if the authentication is complete.
.PARAMETER Client
The authentication client.
.PARAMETER Server
The authentication server to extract token from.
.PARAMETER Token
The next authentication token.
.PARAMETER InputBuffer
A list of additional input buffers.
.PARAMETER OutputBuffer
A list of additional output buffers.
.PARAMETER NoToken
Specify to update with no token in the input buffer.
.PARAMETER PassThru
Specify to passthrough the new context token.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.AuthenticationToken
#>
function Update-LsaClientContext {
    [CmdletBinding(DefaultParameterSetName="FromToken")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Win32.Security.Authentication.IClientAuthenticationContext]$Client,
        [Parameter(Position = 1, Mandatory, ParameterSetName="FromToken", ValueFromPipeline)]
        [NtCoreLib.Win32.Security.Authentication.AuthenticationToken]$Token,
        [Parameter(Position = 1, Mandatory, ParameterSetName="FromContext")]
        [NtCoreLib.Win32.Security.Authentication.IServerAuthenticationContext]$Server,
        [Parameter(Mandatory, ParameterSetName="FromNoToken")]
        [switch]$NoToken,
        [NtCoreLib.Win32.Security.Buffers.SecurityBuffer[]]$InputBuffer = @(),
        [NtCoreLib.Win32.Security.Buffers.SecurityBuffer[]]$OutputBuffer = @(),
        [switch]$PassThru
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromContext" {
            $Client.Continue($Server.Token, $InputBuffer, $OutputBuffer)
        }
        "FromToken" {
            $Client.Continue($Token, $InputBuffer, $OutputBuffer)
        }
        "FromNoToken" {
            $Client.Continue($InputBuffer, $OutputBuffer)
        }
    }
    if ($PassThru) {
        $Client.Token
    }
}

<#
.SYNOPSIS
Update an authentication server.
.DESCRIPTION
This cmdlet updates an authentication server. Returns true if the authentication is complete.
.PARAMETER Server
The authentication server.
.PARAMETER Client
The authentication client to extract token from.
.PARAMETER Token
The next authentication token.
.PARAMETER InputBuffer
A list of additional input buffers.
.PARAMETER OutputBuffer
A list of additional output buffers.
.PARAMETER NoToken
Specify to update with no token in the input buffer.
.PARAMETER PassThru
Specify to passthrough the new context token.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.AuthenticationToken
#>
function Update-LsaServerContext {
    [CmdletBinding(DefaultParameterSetName="FromToken")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Win32.Security.Authentication.IServerAuthenticationContext]$Server,
        [Parameter(Position = 1, Mandatory, ParameterSetName="FromContext")]
        [NtCoreLib.Win32.Security.Authentication.IClientAuthenticationContext]$Client,
        [Parameter(Position = 1, Mandatory, ParameterSetName="FromToken", ValueFromPipeline)]
        [NtCoreLib.Win32.Security.Authentication.AuthenticationToken]$Token,
        [Parameter(Mandatory, ParameterSetName="FromNoToken")]
        [switch]$NoToken,
        [NtCoreLib.Win32.Security.Buffers.SecurityBuffer[]]$InputBuffer = @(),
        [NtCoreLib.Win32.Security.Buffers.SecurityBuffer[]]$OutputBuffer = @(),
        [switch]$PassThru
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromContext" {
            $Server.Continue($Client.Token, $InputBuffer, $OutputBuffer)
        }
        "FromToken" {
            $Server.Continue($Token, $InputBuffer, $OutputBuffer)
        }
        "FromNoToken" {
            $Server.Continue($InputBuffer, $OutputBuffer)
        }
    }
    if ($PassThru) {
        $Server.Token
    }
}

<#
.SYNOPSIS
Get access token for the authentication.
.DESCRIPTION
This cmdlet gets the access token for authentication, once complete.
.PARAMETER Server
The authentication server.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtToken
#>
function Get-LsaAccessToken {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Win32.Security.Authentication.ServerAuthenticationContext]$Server
    )

    $Server.GetAccessToken() | Write-Output
}

<#
.SYNOPSIS
Gets an authentication token.
.DESCRIPTION
This cmdlet gets an authentication token from a context or from 
an array of bytes.
.PARAMETER Context
The authentication context to extract token from. If combined with Token will parse according to
the type of context.
.PARAMETER Token
The array of bytes for the new token.
.PARAMETER Base64Token
The token as a base64 string.
.PARAMETER HexToken
The token as a hex string.
.PARAMETER PackageName
Specify package name for the token.
.PARAMETER Client
Specify the token is from a client.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.AuthenticationToken
#>
function Get-LsaAuthToken {
    [CmdletBinding(DefaultParameterSetName="FromContext")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromBytes")]
        [byte[]]$Token,
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromBase64")]
        [string]$Base64Token,
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromHex")]
        [string]$HexToken,
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromContext")]
        [Parameter(ParameterSetName="FromBytes")]
        [Parameter(ParameterSetName="FromHex")]
        [Parameter(ParameterSetName="FromBase64")]
        [NtCoreLib.Win32.Security.Authentication.IAuthenticationContext]$Context,
        [Parameter(ParameterSetName="FromBytes")]
        [Parameter(ParameterSetName="FromHex")]
        [Parameter(ParameterSetName="FromBase64")]
        [string]$Package,
        [Parameter(ParameterSetName="FromBytes")]
        [Parameter(ParameterSetName="FromHex")]
        [Parameter(ParameterSetName="FromBase64")]
        [switch]$Client
    )

    try {
        if ($PSCmdlet.ParameterSetName -eq "FromContext") {
            $Context.Token | Write-Output
        } else {
            $ba = switch($PSCmdlet.ParameterSetName) {
                "FromBase64" {
                    [System.Convert]::FromBase64String($Base64Token)
                }
                "FromHex" {
                    ConvertFrom-HexDump -Hex $HexToken
                }
                "FromBytes" {
                    $Token
                }
            }
            if ($null -ne $Context) {
                [NtCoreLib.Win32.Security.Authentication.AuthenticationToken]::Parse($Context, $ba)
            } elseif ($null -ne $Package) {
                [NtCoreLib.Win32.Security.Authentication.AuthenticationToken]::Parse($Package, $Client, $ba)
            } else {
                [NtCoreLib.Win32.Security.Authentication.AuthenticationToken]::new($ba)
            }
        }
    } catch {
        Write-Error $_
    }
}

Register-ArgumentCompleter -CommandName Get-LsaAuthToken -ParameterName Package -ScriptBlock $package_completer

<#
.SYNOPSIS
Tests an authentication context to determine if it's complete.
.DESCRIPTION
This cmdlet tests and authentication context to determine if it's complete.
.PARAMETER Context
The authentication context to test.
.INPUTS
None
.OUTPUTS
bool
#>
function Test-LsaContext {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Win32.Security.Authentication.IAuthenticationContext]$Context
    )

    return $Context.Done
}

<#
.SYNOPSIS
Format an authentication token.
.DESCRIPTION
This cmdlet formats an authentication token. Defaults to
a hex dump if format unknown.
.PARAMETER Context
The authentication context to extract token from.
.PARAMETER Token
The authentication token to format.
.PARAMETER AsBytes
Always format as a hex dump.
.PARAMETER AsDER
Always format as a ASN.1 DER structure.
.PARAMETER Key
Specify keys to unprotect the token before formatting.
.INPUTS
None
.OUTPUTS
string
#>
function Format-LsaAuthToken {
    [CmdletBinding(DefaultParameterSetName="FromContext")]
    Param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ParameterSetName="FromToken")]
        [NtCoreLib.Win32.Security.Authentication.AuthenticationToken]$Token,
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromContext")]
        [NtCoreLib.Win32.Security.Authentication.IAuthenticationContext]$Context,
        [switch]$AsBytes,
        [switch]$AsDER,
        [NtCoreLib.Win32.Security.Authentication.AuthenticationKey[]]$Key = @()
    )

    PROCESS {
        if ($PSCmdlet.ParameterSetName -eq "FromContext") {
            $Token = $Context.Token
        }
        if ($Key.Count -gt 0) {
            $Token = Unprotect-LsaAuthToken -Token $Token -Key $Key
        }
        if ($AsBytes) {
            $ba = $Token.ToArray()
            if ($ba.Length -gt 0) {
                Out-HexDump -Bytes $ba -ShowAll
            }
        } elseif ($AsDER) {
            $ba = $Token.ToArray()
            if ($ba.Length -gt 0) {
                Format-ASN1DER -Bytes $ba
            }
        } else {
            $Token.Format() | Write-Output
        }
    }
}

<#
.SYNOPSIS
Exports an authentication token to a file.
.DESCRIPTION
This cmdlet exports an authentication token to a file.
.PARAMETER Context
The authentication context to extract token from.
.PARAMETER Token
The authentication token to export.
.PARAMETER Path
The path to the file to export.
.INPUTS
None
.OUTPUTS
None
#>
function Export-LsaAuthToken {
    [CmdletBinding(DefaultParameterSetName="FromContext")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromToken", ValueFromPipeline)]
        [NtCoreLib.Win32.Security.Authentication.AuthenticationToken]$Token,
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromContext", ValueFromPipeline)]
        [NtCoreLib.Win32.Security.Authentication.IAuthenticationContext]$Context,
        [Parameter(Position = 1, Mandatory)]
        [string]$Path
    )

    if ($PSCmdlet.ParameterSetName -eq "FromContext") {
        $Token = $Context.Token
    }

    $ba = $token.ToArray()
    Write-BinaryFile -Path $Path -Byte $ba
}

<#
.SYNOPSIS
Imports an authentication token from a file.
.DESCRIPTION
This cmdlet imports an authentication token from a file.
.PARAMETER Path
The path to the file to import.
.PARAMETER Context
The authentication context to use to determine the token type.
.PARAMETER Package
The authentication package to use to determine the token type.
.PARAMETER Client
Specifies that the token is from a client. Advisory only.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.AuthenticationToken
#>
function Import-LsaAuthToken {
    [CmdletBinding(DefaultParameterSetName="FromPath")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Path,
        [parameter(Position = 1, ParameterSetName="FromContext", Mandatory)]
        [NtCoreLib.Win32.Security.Authentication.IAuthenticationContext]$Context,
        [parameter(Position = 1, ParameterSetName="FromPackage", Mandatory)]
        [string]$Package,
        [parameter(ParameterSetName="FromContext")]
        [switch]$Client
    )

    $ba = Read-BinaryFile -Path $Path
    switch($PSCmdlet.ParameterSetName) {
        "FromContext" {
            [NtCoreLib.Win32.Security.Authentication.AuthenticationToken]::Parse($Context, $ba)
        }
        "FromPackage" {
            [NtCoreLib.Win32.Security.Authentication.AuthenticationToken]::Parse($Package, $Client, $ba)
        }
        "FromPath" {
            [NtCoreLib.Win32.Security.Authentication.AuthenticationToken]::new($ba)
        }
    }
}

Register-ArgumentCompleter -CommandName Import-LsaAuthToken -ParameterName Package -ScriptBlock $package_completer

<#
.SYNOPSIS
Decrypt an Authentication Token.
.DESCRIPTION
This cmdlet attempts to decrypt an authentication token. The call will return the decrypted token.
This is primarily for Kerberos.
.PARAMETER Key
Specify a keys for decryption.
.PARAMETER Token
The authentication token to decrypt.
.PARAMETER Context
The authentication context which has the token.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.AuthenticationToken
#>
function Unprotect-LsaAuthToken {
    [CmdletBinding(DefaultParameterSetName="FromToken")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromToken", ValueFromPipeline)]
        [NtCoreLib.Win32.Security.Authentication.AuthenticationToken]$Token,
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromContext", ValueFromPipeline)]
        [NtCoreLib.Win32.Security.Authentication.IAuthenticationContext]$Context,
        [Parameter(Position = 1, Mandatory)]
        [NtCoreLib.Win32.Security.Authentication.AuthenticationKey[]]$Key
    )

    if ($PSCmdlet.ParameterSetName -eq "FromContext") {
        $Token = $Context.Token
    }
    $Token.Decrypt($Key) | Write-Output
}

<#
.SYNOPSIS
Get a signature from an authentication context for some message.
.DESCRIPTION
This cmdlet uses an authentication context to generate a message signature. It can be verified using Test-LsaContextSignature.
.PARAMETER Context
Specify the authentication context to use.
.PARAMETER Message
Specify message to sign.
.PARAMETER SequenceNumber
Specify the sequence number for the signature to prevent replay.
.PARAMETER Buffer
Specify the list of buffers to sign.
.INPUTS
byte[]
.OUTPUTS
byte[]
#>
function Get-LsaContextSignature {
    [CmdletBinding(DefaultParameterSetName="FromBytes")]
    param (
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.IAuthenticationContext]$Context,
        [parameter(Mandatory, Position = 1, ValueFromPipeline, ParameterSetName="FromBytes")]
        [byte[]]$Message,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromBuffers")]
        [NtCoreLib.Win32.Security.Buffers.SecurityBuffer[]]$Buffer,
        [parameter(Position = 2)]
        [int]$SequenceNumber = 0
    )

    BEGIN {
        $sig_data = New-Object byte[] -ArgumentList 0
    }

    PROCESS {
        if ($PSCmdlet.ParameterSetName -eq "FromBytes") {
            $sig_data += $Message
        }
    }

    END {
        switch($PSCmdlet.ParameterSetName) {
            "FromBytes" {
                $Context.MakeSignature($sig_data, $SequenceNumber)
            } 
            "FromBuffers" {
                $Context.MakeSignature($Buffer, $SequenceNumber)
            }
        }
    }
}

<#
.SYNOPSIS
Verify a signature from an authentication context for some message.
.DESCRIPTION
This cmdlet uses an authentication context to verify a  signature.
.PARAMETER Context
Specify the authentication context to use.
.PARAMETER Message
Specify message to verify.
.PARAMETER Signature
Specify signature to verify.
.PARAMETER SequenceNumber
Specify the sequence number for the signature to prevent replay.
.PARAMETER Buffer
Specify the list of buffers to sign.
.INPUTS
None
.OUTPUTS
bool
#>
function Test-LsaContextSignature {
    [CmdletBinding(DefaultParameterSetName="FromBytes")]
    param (
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.IAuthenticationContext]$Context,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromBytes")]
        [byte[]]$Message,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromBuffers")]
        [NtCoreLib.Win32.Security.Buffers.SecurityBuffer[]]$Buffer,
        [parameter(Mandatory, Position = 2)]
        [byte[]]$Signature,
        [parameter(Position = 3)]
        [int]$SequenceNumber = 0
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromBytes" {
            $Context.VerifySignature($Message, $Signature, $SequenceNumber)
        }
        "FromBuffers" {
            $Context.VerifySignature($Buffer, $Signature, $SequenceNumber)
        }
    }
}

<#
.SYNOPSIS
Encrypt some message for an authentication context.
.DESCRIPTION
This cmdlet uses an authentication context to encrypt some message. It returns both the encrypted message and a signature.
It can be decrypted using Unprotect-LsaContextMessage. If you use buffers only the signature is returned from the command
and the encrypted data is updated in place.
.PARAMETER Context
Specify the authentication context to use.
.PARAMETER Message
Specify message to encrypt.
.PARAMETER SequenceNumber
Specify the sequence number for the encryption to prevent replay.
.PARAMETER QualityOfProtection
Specify flags for the encryption operation. For example wrap but don't encrypt.
.PARAMETER NoSignature
Specify to not automatically generate a signature buffer. You'll need to specify it in the buffers.
.INPUTS
byte[]
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.EncryptedMessage
#>
function Protect-LsaContextMessage {
    [CmdletBinding(DefaultParameterSetName="FromBytes")]
    param (
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.IAuthenticationContext]$Context,
        [parameter(Mandatory, Position = 1, ValueFromPipeline, ParameterSetName="FromBytes")]
        [byte[]]$Message,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromBuffers")]
        [NtCoreLib.Win32.Security.Buffers.SecurityBuffer[]]$Buffer,
        [parameter(Position = 2)]
        [int]$SequenceNumber = 0,
        [NtCoreLib.Win32.Security.Authentication.SecurityQualityOfProtectionFlags]$QualityOfProtection = 0,
        [parameter(ParameterSetName="FromBuffers")]
        [switch]$NoSignature
    )

    BEGIN {
        $enc_data = New-Object byte[] -ArgumentList 0
    }

    PROCESS {
        if ($PSCmdlet.ParameterSetName -eq "FromBytes") {
            $enc_data += $Message
        }
    }

    END {
        switch($PSCmdlet.ParameterSetName) {
            "FromBytes" {
                $Context.EncryptMessage($enc_data, $QualityOfProtection, $SequenceNumber)
            }
            "FromBuffers" {
                if ($NoSignature) {
                    $Context.EncryptMessageNoSignature($Buffer, $QualityOfProtection, $SequenceNumber)
                } else {
                    $Context.EncryptMessage($Buffer, $QualityOfProtection, $SequenceNumber)
                }
            }
        }
    }
}

<#
.SYNOPSIS
Decrypt some message from an authentication context.
.DESCRIPTION
This cmdlet uses an authentication context to decrypt some message as well as verify a signature.
If using buffers the data is decrypted in place.
.PARAMETER Context
Specify the authentication context to use.
.PARAMETER Message
Specify message to decrypt.
.PARAMETER Signature
Specify signature to verify.
.PARAMETER SequenceNumber
Specify the sequence number for the encryption to prevent replay.
.PARAMETER NoSignature
Specify to not include a signature automatically in the buffers.
.INPUTS
None
.OUTPUTS
byte[]
#>
function Unprotect-LsaContextMessage {
    [CmdletBinding(DefaultParameterSetName="FromBytes")]
    param (
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.IAuthenticationContext]$Context,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromBytes")]
        [byte[]]$Message,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromBuffers")]
        [parameter(Mandatory, Position = 1, ParameterSetName="FromBuffersNoSig")]
        [NtCoreLib.Win32.Security.Buffers.SecurityBuffer[]]$Buffer,
        [parameter(Mandatory, Position = 2, ParameterSetName="FromBytes")]
        [parameter(Mandatory, Position = 2, ParameterSetName="FromBuffers")]
        [byte[]]$Signature,
        [parameter(Mandatory, ParameterSetName="FromBuffersNoSig")]
        [switch]$NoSignature,
        [parameter(Position = 3)]
        [int]$SequenceNumber = 0
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromBytes" {
            $msg = [NtCoreLib.Win32.Security.Authentication.EncryptedMessage]::new($Message, $Signature)
            $Context.DecryptMessage($msg, $SequenceNumber)
        }
        "FromBuffers" {
            $Context.DecryptMessage($Buffer, $Signature, $SequenceNumber)
        }
        "FromBuffersNoSig" {
            $Context.DecryptMessageNoSignature($Buffer, $SequenceNumber)
        }
    }
}

<#
.SYNOPSIS
Create a new security buffer based on existing data or for output.
.DESCRIPTION
This cmdlet creates a new security object either containing existing data for input/output or and output only buffer.
.PARAMETER Type
Specify the type of the buffer.
.PARAMETER Byte
Specify the existing bytes for the buffer.
.PARAMETER Size
Specify the size of a buffer for an output buffer.
.PARAMETER ChannelBinding
Specify a channel binding token.
.PARAMETER Token
Specify a buffer which is an authentication token.
.PARAMETER String
Specify a buffer derived from a string.
.PARAMETER Encoding
Specify the character encoding when making a buffer from a string.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Buffers.SecurityBuffer
#>
function New-LsaSecurityBuffer {
    [CmdletBinding(DefaultParameterSetName="FromBytes")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName="FromBytes")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromSize")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromString")]
        [parameter(ParameterSetName="FromEmpty")]
        [NtCoreLib.Win32.Security.Buffers.SecurityBufferType]$Type = 0,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromBytes")]
        [byte[]]$Byte,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromSize")]
        [int]$Size,
        [parameter(Mandatory, ParameterSetName="FromEmpty")]
        [switch]$Empty,
        [parameter(Mandatory, ParameterSetName="FromChannelBinding")]
        [NtObjectManager.Utils.ChannelBindingHolder]$ChannelBinding,
        [Parameter(Mandatory, ParameterSetName="FromToken")]
        [NtCoreLib.Win32.Security.Authentication.AuthenticationToken]$Token,
        [parameter(Mandatory, ParameterSetName="FromString")]
        [string]$String,
        [parameter(ParameterSetName="FromString")]
        [string]$Encoding = "Unicode",
        [parameter(ParameterSetName="FromBytes")]
        [parameter(ParameterSetName="FromString")]
        [Parameter(ParameterSetName="FromToken")]
        [switch]$ReadOnly,
        [parameter(ParameterSetName="FromBytes")]
        [parameter(ParameterSetName="FromString")]
        [Parameter(ParameterSetName="FromToken")]
        [switch]$ReadOnlyWithChecksum
    )

    $type_flags = if ($PSCmdlet.ParameterSetName -eq "FromToken") {
        [NtCoreLib.Win32.Security.Buffers.SecurityBufferType]::Token
    } else {
        $Type
    }
    if ($ReadOnly) {
        $type_flags = $type_flags -bor [NtCoreLib.Win32.Security.Buffers.SecurityBufferType]::ReadOnly
    }
    if ($ReadOnlyWithChecksum) {
        $type_flags = $type_flags -bor [NtCoreLib.Win32.Security.Buffers.SecurityBufferType]::ReadOnlyWithChecksum
    }

    switch($PSCmdlet.ParameterSetName) {
        "FromBytes" {
            [NtCoreLib.Win32.Security.Buffers.SecurityBufferInOut]::new($type_flags, $Byte)
        }
        "FromSize" {
            [NtCoreLib.Win32.Security.Buffers.SecurityBufferOut]::new($type_flags, $Size)
        }
        "FromEmpty" {
            [NtCoreLib.Win32.Security.Buffers.SecurityBufferOut]::new($type_flags, 0)
        }
        "FromChannelBinding" {
            [NtCoreLib.Win32.Security.Buffers.SecurityBufferChannelBinding]::new($ChannelBinding)
        }
        "FromToken" {
            [NtCoreLib.Win32.Security.Buffers.SecurityBufferInOut]::new($type_flags, $Token.ToArray())
        }
        "FromString" {
            [NtCoreLib.Win32.Security.Buffers.SecurityBufferInOut]::new($type_flags, [System.Text.Encoding]::GetEncoding($Encoding).GetBytes($String))
        }
    }
}

<#
.SYNOPSIS
Convert a security buffer to another format.
.DESCRIPTION
This cmdlet converts a security buffer to another format, either a byte array, string or authentication token.
.PARAMETER Buffer
The buffer to convert.
.PARAMETER AsString
Specify to convert the string as bytes.
.PARAMETER Encoding
Specify the character encoding when converting to a string.
.PARAMETER AsToken
Specify to convert the buffer to an authentication token.
.INPUTS
NtCoreLib.Win32.Security.Buffers.SecurityBuffer
.OUTPUTS
byte[]
string
NtCoreLib.Win32.Security.Authentication.AuthenticationToken
#>
function ConvertFrom-LsaSecurityBuffer {
    [CmdletBinding(DefaultParameterSetName="ToBytes")]
    param (
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Win32.Security.Buffers.SecurityBuffer]$Buffer,
        [parameter(Mandatory, ParameterSetName="ToString")]
        [switch]$AsString,
        [parameter(ParameterSetName="ToString")]
        [string]$Encoding = "Unicode",
        [parameter(Mandatory, ParameterSetName="ToToken")]
        [switch]$AsToken
    )

    PROCESS {
        switch($PSCmdlet.ParameterSetName) {
            "ToBytes" {
                $Buffer.ToArray() | Write-Output -NoEnumerate
            }
            "ToString" {
                [System.Text.Encoding]::GetEncoding($Encoding).GetString($Buffer.ToArray())
            }
            "ToToken" {
                Get-LsaAuthToken -Token $Buffer.ToArray()
            }
        }
    }
}

<#
.SYNOPSIS
Get an LSA policy object.
.DESCRIPTION
This cmdlet gets an LSA policy object for a specified system and access rights.
.PARAMETER SystemName
Specify the target system.
.PARAMETER Access
Specify the access rights on the policy.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Policy.LsaPolicy
.EXAMPLE
Get-LsaPolicy
Get the local LSA policy object with maximum access.
.EXAMPLE
Get-LsaPolicy -SystemName "PRIMARYDC"
Get the LSA policy object on the system PRIMARYDC with maximum access.
.EXAMPLE
Get-LsaPolicy -Access LookupNames
Get the local LSA policy object with LookupNames access.
#>
function Get-LsaPolicy { 
    [CmdletBinding()]
    param(
        [NtCoreLib.Win32.Security.Policy.LsaPolicyAccessRights]$Access = "MaximumAllowed",
        [string]$SystemName
    )

    [NtCoreLib.Win32.Security.Policy.LsaPolicy]::Open($SystemName, $Access)
}

<#
.SYNOPSIS
Get an account object from an LSA policy.
.DESCRIPTION
This cmdlet opens an account object from a LSA policy.
.PARAMETER Policy
Specify the policy to get the account from.
.PARAMETER Access
Specify the access rights on the account object.
.PARAMETER InfoOnly
Specify to only get account information not objects.
.PARAMETER Sid
Specify to get account by SID.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Policy.LsaAccount
.EXAMPLE
Get-LsaAccount -Policy $policy
Get all accessible account objects in the policy.
.EXAMPLE
Get-LsaAccount -Policy $policy -InfoOnly
Get all information only account objects in the policy.
.EXAMPLE
Get-LsaAccount -Policy $policy -Sid "S-1-2-3-4"
Get the account object by SID.
#>
function Get-LsaAccount { 
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Policy.LsaPolicy]$Policy,
        [Parameter(Mandatory, Position = 1, ParameterSetName="FromSid")]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [Parameter(ParameterSetName="All")]
        [Parameter(ParameterSetName="FromSid")]
        [NtCoreLib.Win32.Security.Policy.LsaAccountAccessRights]$Access = "MaximumAllowed",
        [Parameter(Mandatory, ParameterSetName="AllInfoOnly")]
        [switch]$InfoOnly
    )

    if ($InfoOnly) {
        $Policy.EnumerateAccounts() | Write-Output
    } else {
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Policy.OpenAccessibleAccounts($Access) | Write-Output
            }
            "FromSid" {
                $Policy.OpenAccount($Sid, $Access)
            }
        }
    }
}

<#
.SYNOPSIS
Get a trusted domain object from an LSA policy.
.DESCRIPTION
This cmdlet opens a trusted domain object from a LSA policy.
.PARAMETER Policy
Specify the policy to get the trusted domain from.
.PARAMETER Access
Specify the access rights on the trusted domain object.
.PARAMETER InfoOnly
Specify to only get trusted domain information not objects.
.PARAMETER Sid
Specify to get trusted domain by SID.
.PARAMETER Name
Specify to get trusted domain by name.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Policy.LsaTrustedDomain
.EXAMPLE
Get-LsaTrustedDomain -Policy $policy
Get all accessible trusted domain objects in the policy.
.EXAMPLE
Get-LsaTrustedDomain -Policy $policy -InfoOnly
Get all information only trusted domain objects in the policy.
.EXAMPLE
Get-LsaTrustedDomain -Policy $policy -Sid "S-1-2-3"
Get the trusted domain object by SID.
.EXAMPLE
Get-LsaTrustedDomain -Policy $policy -Name "domain.local"
Get the trusted domain object by name.
#>
function Get-LsaTrustedDomain { 
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Policy.LsaPolicy]$Policy,
        [Parameter(Mandatory, ParameterSetName="FromSid")]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [Parameter(Mandatory, Position = 1, ParameterSetName="FromName")]
        [string]$Name,
        [Parameter(ParameterSetName="All")]
        [Parameter(ParameterSetName="FromSid")]
        [Parameter(ParameterSetName="FromName")]
        [NtCoreLib.Win32.Security.Policy.LsaTrustedDomainAccessRights]$Access = "MaximumAllowed",
        [Parameter(Mandatory, ParameterSetName="AllInfoOnly")]
        [switch]$InfoOnly
    )

    if ($InfoOnly) {
        $Policy.EnumerateTrustedDomains() | Write-Output
    } else {
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Policy.OpenAccessibleTrustedDomains($Access) | Write-Output
            }
            "FromSid" {
                $Policy.OpenTrustedDomain($Sid, $Access)
            }
            "FromName" {
                $Policy.OpenTrustedDomain($Name, $Access)
            }
        }
    }
}

<#
.SYNOPSIS
Get a secret object from an LSA policy.
.DESCRIPTION
This cmdlet opens a secret object from a LSA policy.
.PARAMETER Policy
Specify the policy to get the secret from.
.PARAMETER Access
Specify the access rights on the secret object.
.PARAMETER Name
Specify to get trusted domain by name.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Policy.LsaSecret
.EXAMPLE
Get-LsaSecret -Policy $policy -Name '$SECRET_NAME'
Get the secret by name.
#>
function Get-LsaSecret { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Policy.LsaPolicy]$Policy,
        [Parameter(Mandatory, Position = 1)]
        [string]$Name,
        [NtCoreLib.Win32.Security.Policy.LsaSecretAccessRights]$Access = "MaximumAllowed"
    )

    $Policy.OpenSecret($Name, $Access)
}

<#
.SYNOPSIS
Lookup one or more SIDs by name from the policy.
.DESCRIPTION
This cmdlet looks up one or more SIDs from a LSA policy.
.PARAMETER Policy
Specify the policy to get the SIDs from.
.PARAMETER Name
Specify the names to lookup.
.PARAMETER Flags
Specify flags for the looked up names.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.SidName[]
.EXAMPLE
Get-LsaSid -Policy $policy -Name 'Administrator'
Lookup the name Administrator in the policy.
#>
function Get-LsaSid { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Policy.LsaPolicy]$Policy,
        [Parameter(Mandatory, Position = 1)]
        [string[]]$Name,
        [NtCoreLib.Win32.Security.Policy.LsaLookupNameOptionFlags]$Flags = 0
    )

    $Policy.LookupNames($Name, $Flags) | Write-Output
}

<#
.SYNOPSIS
Lookup one or more names by SID from the policy.
.DESCRIPTION
This cmdlet looks up one or more names from a LSA policy.
.PARAMETER Policy
Specify the policy to get the names from.
.PARAMETER Sid
Specify the SIDs to lookup.
.PARAMETER Flags
Specify flags for the looked up SIDs.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.SidName[]
.EXAMPLE
Get-LsaName -Policy $policy -Sid 'S-1-5-32-544'
Lookup the SID S-1-5-32-544 in the policy.
#>
function Get-LsaName { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Policy.LsaPolicy]$Policy,
        [Parameter(Mandatory, Position = 1)]
        [NtCoreLib.Security.Authorization.Sid[]]$Sid,
        [NtCoreLib.Win32.Security.Policy.LsaLookupSidOptionFlags]$Flags = 0
    )

    if ($Flags -ne 0) {
        $Policy.LookupSids2($Sid, $Flags) | Write-Output
    } else {
        $Policy.LookupSids($Sid) | Write-Output
    }
}

<#
.SYNOPSIS
Get a LSA private data (secret) object.
.DESCRIPTION
This cmdlet gets the private data from an LSA policy.
.PARAMETER SystemName
Specify the target system.
.PARAMETER Name
Specify the name of the private data.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
Get-LsaPrivateData -Name "MYSECRET"
Get the LSA private data MYSECRET.
.EXAMPLE
Get-LsaPrivateData -Name "MYSECRET" -SystemName PRIMARYDC
Get the LSA private data MYSECRET from the PRIMARYDC.
#>
function Get-LsaPrivateData { 
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Name,
        [string]$SystemName
    )

    [NtCoreLib.Win32.Security.Win32Security]::LsaRetrievePrivateData($SystemName, $Name)
}

<#
.SYNOPSIS
Set a LSA private data (secret) object.
.DESCRIPTION
This cmdlet sets the private data for an LSA policy.
.PARAMETER SystemName
Specify the target system.
.PARAMETER Name
Specify the name of the private data.
.PARAMETER Data
Specify the data to set.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-LsaPrivateData -Name "MYSECRET" -Data 0, 1, 2, 3
Set the LSA private data MYSECRET.
.EXAMPLE
Set-LsaPrivateData -Name "MYSECRET" -SystemName PRIMARYDC -Data 0, 1, 2, 3
Set the LSA private data MYSECRET on PRIMARYDC.
#>
function Set-LsaPrivateData { 
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Name,
        [Parameter(Position = 1, Mandatory)]
        [byte[]]$Data,
        [string]$SystemName
    )

    [NtCoreLib.Win32.Security.Win32Security]::LsaStorePrivateData($SystemName, $Name, $Data)
}


<#
.SYNOPSIS
Get registered WNF subscription.
.DESCRIPTION
This cmdlet gets the registered WNF entries or a specific entry from a state name.
.PARAMETER StateName
The statename to get.
.PARAMETER DontCheckExists
Specify to not check that the WNF entry exists.
.PARAMETER Name
Lookup the state name from a well known text name.
.OUTPUTS
NtCoreLib.NtWnf
.EXAMPLE
Get-NtWnf
Get all registered WNF entries.
.EXAMPLE
Get-NtWnf 0x12345678
Get a WNF entry from a state name.
.EXAMPLE
Get-NtWnf 0x12345678 -DontCheckExists
Get a WNF entry from a state name but don't check if it exists.
.EXAMPLE
Get-NtWnf "WNF_AOW_BOOT_PROGRESS"
Get a WNF entry from a name.
#>
function Get-NtWnf {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Position = 0, Mandatory, ParameterSetName = "StateName")]
        [uint64]$StateName,
        [parameter(ParameterSetName = "StateName")]
        [parameter(ParameterSetName = "Name")]
        [switch]$DontCheckExists,
        [parameter(Position = 0, Mandatory, ParameterSetName = "Name")]
        [string]$Name
    )
    switch ($PSCmdlet.ParameterSetName) {
        "All" {
            [NtCoreLib.NtWnf]::GetRegisteredNotifications()
        }
        "StateName" {
            [NtCoreLib.NtWnf]::Open($StateName, -not $DontCheckExists)
        }
        "Name" {
            [NtCoreLib.NtWnf]::Open($Name, -not $DontCheckExists)
        }
    }
}

<#
.SYNOPSIS
Open a file using the Win32 CreateFile API.
.DESCRIPTION
This cmdlet opens a file using the Win32 CreateFile API rather than the native APIs.
.PARAMETER Path
Specify the path to open. Note that the function doesn't resolve relative paths from the PS working directory.
.PARAMETER DesiredAccess
Specify the desired access for the handle.
.PARAMETER ShareMode
Specify the share mode for the file.
.PARAMETER SecurityDescriptor
Specify an optional security descriptor.
.PARAMETER InheritHandle
Specify that the file handle should be inheritable.
.PARAMETER Disposition
Specify the file open disposition.
.PARAMETER FlagsAndAttributes
Specify flags and attributes for the open.
.PARAMETER TemplateFile
Specify a template file to copy certain properties from.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtFile
.EXAMPLE
Get-Win32File -Path c:\abc\xyz.txt
Open the existing file c:\abc\xyz.txt
#>
function Get-Win32File {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$Path,
        [NtCoreLib.FileAccessRights]$DesiredAccess = "MaximumAllowed",
        [NtCoreLib.FileShareMode]$ShareMode = 0,
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [switch]$InheritHandle,
        [NtCoreLib.Win32.IO.CreateFileDisposition]$Disposition = "OpenExisting",
        [NtCoreLib.Win32.IO.CreateFileFlagsAndAttributes]$FlagsAndAttributes = 0,
        [NtCoreLib.NtFile]$TemplateFile
    )

    [NtCoreLib.Win32.IO.Win32FileUtils]::CreateFile($Path, $DesiredAccess, $ShareMode, `
            $SecurityDescriptor, $InheritHandle, $Disposition, $FlagsAndAttributes, $TemplateFile)
}

<#
.SYNOPSIS
Start an accessible scheduled task.
.DESCRIPTION
This cmdlet starts a scheduled task based on an accessible task result.
.PARAMETER Task
Specify the task to start.
.PARAMETER User
Specify the user to run the task under. Can be a username or a SID.
.PARAMETER Flags
Specify optional flags.
.PARAMETER SessionId
Specify an optional session ID.
.PARAMETER Arguments
Specify optional arguments to the pass to the task.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Start-AccessibleScheduledTask -Task $task
Start a task with no options.
.EXAMPLE
Start-AccessibleScheduledTask -Task $task -Arguments "A", B"
Start a task with optional argument strings "A" and "B"
#>
function Start-AccessibleScheduledTask {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtObjectManager.Cmdlets.Accessible.ScheduledTaskAccessCheckResult]$Task,
        [string]$User,
        [NtObjectManager.Utils.ScheduledTask.TaskRunFlags]$Flags = 0,
        [int]$SessionId,
        [string[]]$Arguments
    )

    $Task.RunEx($Flags, $SessionId, $User, $Arguments)
}

<#
.SYNOPSIS
Gets entries from an object directory.
.DESCRIPTION
This cmdlet gets the list entries in an object directory.
.PARAMETER Directory
Specify the directory.
.INPUTS
None
.OUTPUTS
NtCoreLib.ObjectDirectoryInformation[]
.EXAMPLE
Get-NtDirectoryEntry $dir
Get list of entries from $dir.
#>
function Get-NtDirectoryEntry {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.NtDirectory]$Directory
    )

    $Directory.Query() | Write-Output
}

<#
.SYNOPSIS
Terminates a job object.
.DESCRIPTION
This cmdlet terminates a job object and all it's processes.
.PARAMETER Job
Specify a Job object to terminate.
.PARAMETER Status
Specify the NT status code to terminate with.
.INPUTS
None
.OUTPUTS
Bool
.EXAMPLE
Stop-NtJob -Job $job
Terminate a job with STATUS_SUCCESS code.
.EXAMPLE
Stop-NtJob -Job $job -Status STATUS_ACCESS_DENIED
Terminate a job with STATUS_ACCESS_DENIED code.
#>
function Stop-NtJob {
    param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtJob]$Job,
        [parameter(Position = 1)]
        [NtCoreLib.NtStatus]$Status = 0
    )
    $Job.Terminate($Status)
}

<#
.SYNOPSIS
Call a method in an enclave.
.DESCRIPTION
This cmdlet calls a method in an enclave.
.PARAMETER Routine
Specify the enclave routine to call.
.PARAMETER Parameter
Specify parameter to pass to the routine.
.PARAMETER WaitForThread
Specify to wait for an idle thread before calling.
.INPUTS
None
.OUTPUTS
int64
#>
function Invoke-NtEnclave {
    param(
        [Parameter(Position = 0, Mandatory)]
        [int64]$Routine,
        [int64]$Parameter = 0,
        [switch]$WaitForThread
    )

    [NtCoreLib.NtEnclave]::Call($Routine, $Parameter, $WaitForThread)
}

<#
.SYNOPSIS
Create a new memory buffer.
.DESCRIPTION
This cmdlet creates a new memory buffer object of a certain size.
.PARAMETER Length
Specify the length in bytes of the buffer.
.INPUTS
None
.OUTPUTS
NtCoreLib.Native.SafeBuffers.SafeHGlobalBuffer
#>
function New-Win32MemoryBuffer {
    param(
        [Parameter(Position = 0, Mandatory)]
        [int]$Length
    )

    [NtCoreLib.Native.SafeBuffers.SafeHGlobalBuffer]::new($Length)
}

<#
.SYNOPSIS
Open a filter communications port.
.DESCRIPTION
This cmdlet opens a filter communication port by name.
.PARAMETER Path
Specify the path to the filter communication port.
.PARAMETER SyncHandle
Specify to make the handle synchronous.
.PARAMETER Context
Specify optional context buffer.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Filter.FilterConnectionPort
.EXAMPLE
Get-FilterConnectionPort -Path "\FilterDriver"
Open the filter communication port named \FilterDriver.
#>
function Get-FilterConnectionPort {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$Path,
        [switch]$SyncHandle,
        [byte[]]$Context = $null
    )

    [NtCoreLib.Win32.Filter.FilterConnectionPort]::Open($Path, $SyncHandle, $Context) | Write-Output
}

<#
.SYNOPSIS
Sends a message to a filter connection port.
.DESCRIPTION
This cmdlet sends and receives a message on a filter connection port.
.PARAMETER Port
Specify the port to send on.
.PARAMETER Input
Optional input data.
.PARAMETER MaximumOutput
Specify maximum output data.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
Send-FilterConnectionPort -Port $port -Input @(1, 2, 3, 4) -MaximumOutput 100
Send a 4 byte message and receive at most 100 bytes.
#>
function Send-FilterConnectionPort {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Filter.FilterConnectionPort]$Port,
        [byte[]]$Input = $null,
        [int]$MaximumOutput = 0
    )

    $Port.SendMessage($Input, $MaximumOutput) | Write-Output -NoEnumerate
}

<#
.SYNOPSIS
Get list of filter drivers loaded on the system.
.DESCRIPTION
This cmdlet enumerates the list of filter drivers loaded on the system.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Filter.FilterDriver[]
.EXAMPLE
Get-FilterDriver
Get list of filter drivers.
#>
function Get-FilterDriver {
    [NtCoreLib.Win32.Filter.FilterManagerUtils]::GetFilterDrivers() | Write-Output
}

<#
.SYNOPSIS
Get list of filter driver instances on the system.
.DESCRIPTION
This cmdlet enumerates the list of filter driver instances for a specified filter driver.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Filter.FilterInstance[]
.EXAMPLE
Get-FilterDriverInstance 
Get list of filter driver instances for all filter drivers.
.EXAMPLE
Get-FilterDriverInstance -FilterName "luafv"
Get list of filter driver instances for the "luafv" driver.
#>
function Get-FilterDriverInstance {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromName")]
        [string]$FilterName
    )

    switch($PSCmdlet.ParameterSetName) {
        "All" {
            [NtCoreLib.Win32.Filter.FilterManagerUtils]::GetFilterDriverInstances() | Write-Output
        }
        "FromName" {
            [NtCoreLib.Win32.Filter.FilterManagerUtils]::GetFilterDriverInstances($FilterName) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get list of filter driver instances on the system.
.DESCRIPTION
This cmdlet enumerates the list of filter driver instances for a specified filter driver.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Filter.FilterVolume[]
.EXAMPLE
Get-FilterDriverVolume 
Get list of filter driver volumes.
#>
function Get-FilterDriverVolume {
    [NtCoreLib.Win32.Filter.FilterManagerUtils]::GetFilterVolumes() | Write-Output
}

<#
.SYNOPSIS
Get list of filter driver volume instances on the system.
.DESCRIPTION
This cmdlet enumerates the list of filter driver volume instances for a specified filter driver.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Filter.FilterInstance[]
.EXAMPLE
Get-FilterDriverVolumeInstance 
Get list of filter driver instances for all filter driver volumes.
.EXAMPLE
Get-FilterDriverInstance -VolumeName "C:\"
Get list of filter driver volume instances for the C: drive.
#>
function Get-FilterDriverVolumeInstance {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromName")]
        [string]$VolumeName
    )

    switch($PSCmdlet.ParameterSetName) {
        "All" {
            [NtCoreLib.Win32.Filter.FilterManagerUtils]::GetFilterVolumeInstances() | Write-Output
        }
        "FromName" {
            [NtCoreLib.Win32.Filter.FilterManagerUtils]::GetFilterVolumeInstances($VolumeName) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get the device setup classes.
.DESCRIPTION
This cmdlet gets device setup classes, either all installed or from a GUID/Name.
.PARAMETER Name
The name of the setup class.
.PARAMETER Class
The GUID of the setup class.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Device.DeviceSetupClass
.EXAMPLE
Get-NtDeviceSetupClass
Get all device setup classes.
.EXAMPLE
Get-NtDeviceSetupClass -Class '6BDD1FC1-810F-11D0-BEC7-08002BE20920'
Get the device setup class for the specified GUID.
.EXAMPLE
Get-NtDeviceSetupClass -Name 'USB'
Get the device setup class for the USB class.
#>
function Get-NtDeviceSetupClass {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromName")]
        [string]$Name,
        [parameter(Mandatory, ParameterSetName = "FromClass", ValueFromPipelineByPropertyName)]
        [guid]$Class
    )

    PROCESS {
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceSetupClasses() | Write-Output
            }
            "FromName" {
                [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceSetupClasses() | Where-Object Name -eq $Name | Write-Output
            }
            "FromClass" {
                [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceSetupClass($Class) | Write-Output
            }
        }
    }
}

<#
.SYNOPSIS
Get the device interface classes.
.DESCRIPTION
This cmdlet gets device interface classes, either all installed or from a GUID.
.PARAMETER Class
The GUID of the interface class.
.PARAMETER All
Get all devices including ones not present.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Device.DeviceInterfaceClass
.EXAMPLE
Get-NtDeviceInterfaceClass
Get all device interface classes.
.EXAMPLE
Get-NtDeviceInterfaceClass -Class '6BDD1FC1-810F-11D0-BEC7-08002BE20920'
Get the device interface class for the specified GUID.
#>
function Get-NtDeviceInterfaceClass {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromClass")]
        [guid]$Class,
        [switch]$All
    )

    switch($PSCmdlet.ParameterSetName) {
        "All" {
            [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceInterfaceClasses($All) | Write-Output
        }
        "FromClass" {
            [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceInterfaceClass($Class, $All) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get the device node.
.DESCRIPTION
This cmdlet gets device nodes, either all present or from a GUID/Name.
.PARAMETER Class
The GUID of the setup class.
.PARAMETER All
Get all device instances. The default is to only get present instances.
.PARAMETER Tree
Get all device nodes as a tree.
.PARAMETER InstanceId
Get device from instance ID.
.PARAMETER LinkName
Specify a symbolic link name to resolve the device node.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Device.DeviceNode
.EXAMPLE
Get-NtDeviceNode
Get all present device instances.
.EXAMPLE
Get-NtDeviceNode -All
Get all device instances.
.EXAMPLE
Get-NtDeviceNode -Class '6BDD1FC1-810F-11D0-BEC7-08002BE20920'
Get the device instances class for the specified setup class GUID.
.EXAMPLE
Get-NtDeviceNode -Tree
Get all device instances in a tree structure.
.EXAMPLE
Get-NtDeviceNode -PDOName \Device\HarddiskVolume3
Get the device node with a specified PDO.
.EXAMPLE
Get-NtDeviceNode -LinkName \??\C: 
Get the device node with a specified symbolic link.
#>
function Get-NtDeviceNode {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromClass", ValueFromPipelineByPropertyName)]
        [guid]$Class,
        [parameter(ParameterSetName = "FromClass")]
        [parameter(ParameterSetName = "All")]
        [switch]$All,
        [parameter(Mandatory, ParameterSetName = "FromTree")]
        [switch]$Tree,
        [parameter(Mandatory, ParameterSetName = "FromInstanceId")]
        [string]$InstanceId,
        [parameter(Mandatory, ParameterSetName = "FromPDOName")]
        [string]$PDOName,
        [parameter(ParameterSetName = "FromLinkName")]
        [string]$LinkName
    )

    PROCESS {
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceNodeList($All) | Write-Output
            }
            "FromClass" {
                [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceNodeList($Class, $All) | Write-Output
            }
            "FromTree" {
                [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceNodeTree() | Write-Output
            }
            "FromInstanceId" {
                [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceNode($InstanceId) | Write-Output
            }
            "FromPDOName" {
                Get-NtDeviceNode | Where-Object PDOName -eq $PDOName
            }
            "FromLinkName" {
                try { 
                    $PDOName = Get-NtSymbolicLinkTarget -Path $LinkName -Resolve
                    Get-NtDeviceNode | Where-Object PDOName -eq $PDOName
                } catch {
                    Write-Error $_
                }
            }
        }
    }
}

<#
.SYNOPSIS
Get device properties.
.DESCRIPTION
This cmdlet gets device properties.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Device.DeviceProperty[]
.EXAMPLE
Get-NtDeviceProperty -Device $dev
Get all properties for a device.
#>
function Get-NtDeviceProperty {
    [CmdletBinding(DefaultParameterSetName = "FromDevice")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromDevice", ValueFromPipeline)]
        [NtCoreLib.Win32.Device.IDevicePropertyProvider]$Device
    )

    PROCESS {
        switch($PSCmdlet.ParameterSetName) {
            "FromDevice" {
                $Device.GetProperties() | Write-Output
            }
        }
    }
}

<#
.SYNOPSIS
Get device node children.
.DESCRIPTION
This cmdlet gets device node children.
.PARAMETER Node
The device node to query the children for.
.PARAMETER Recurse
Recursively get child nodes.
.PARAMETER Depth
Specify the maximum depth for the recursion.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Device.DeviceTreeNode[]
.EXAMPLE
Get-NtDeviceNodeChild -Node $dev
Get all children for a device node
.EXAMPLE
Get-NtDeviceNodeChild -Node $dev -Recurse
Get all children for a device node recursively.
.EXAMPLE
Get-NtDeviceNodeChild -Node $dev -Recurse -Depth 2
Get all children for a device node recursively with max depth of 2.
#>
function Get-NtDeviceNodeChild {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromNode", Position = 0)]
        [NtCoreLib.Win32.Device.DeviceNode]$Node,
        [switch]$Recurse,
        [int]$Depth = [int]::MaxValue
    )

    if ($Recurse -and $Depth -lt 1) {
        return
    }

    try
    {
        if ($Node -isNot [NtCoreLib.Win32.Device.DeviceTreeNode]) {
            $Node = [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceNodeTree($Node.InstanceId)
        }

        switch($PSCmdlet.ParameterSetName) {
            "FromNode" {
                if ($Recurse) {
                    $recdepth = $Depth - 1
                    $Device.Children | ForEach-Object { Get-NtDeviceNodeChild -Node $_ -Recurse -Depth $recdepth }
                }
                $Node.Children | Write-Output
            }
        }
    }
    catch 
    {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get device instance parent.
.DESCRIPTION
This cmdlet gets device node parent.
.PARAMETER Node
The device node to query the parent for.
.PARAMETER Recurse
Get all parents recursively.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Device.DeviceNode[]
.EXAMPLE
Get-NtDeviceNodeParent -Node $dev
Get parent for device node.
.EXAMPLE
Get-NtDeviceNodeParent -Node $dev -Recurse
Get all parents for device node.
#>
function Get-NtDeviceNodeParent {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromNode", Position = 0)]
        [NtCoreLib.Win32.Device.DeviceNode]$Node,
        [switch]$Recurse
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromNode" {
            if ($Recurse) {
                $Node.GetParentNodes() | Write-Output
            } else {
                $Node.Parent | Write-Output
            }
        }
    }
}

<#
.SYNOPSIS
Get device stack for a node.
.DESCRIPTION
This cmdlet gets device node's device stack.
.PARAMETER Node
The device node to query device stack for.
.PARAMETER Summary
Summarize the device stack as a single line.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Device.DeviceStackEntry[]
.EXAMPLE
Get-NtDeviceNodeStack -Node $dev
Get device stack for device node.
#>
function Get-NtDeviceNodeStack {
    [CmdletBinding(DefaultParameterSetName = "FromNode")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromNode", Position = 0, ValueFromPipeline)]
        [NtCoreLib.Win32.Device.DeviceNode]$Node,
        [switch]$Summary
    )

    PROCESS {
        switch($PSCmdlet.ParameterSetName) {
            "FromNode" {
                if ($Summary) {
                    [string]::Join(", ", $Node.DeviceStack) | Write-Output
                } else {
                    $Node.DeviceStack | Write-Output
                }
            }
        }
    }
}

<#
.SYNOPSIS
Get the device interface instances.
.DESCRIPTION
This cmdlet gets device interface instances either all present, from a GUID or instance name.
.PARAMETER Class
The GUID of the interface class.
.PARAMETER Instance
The path the instance symbolic link.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Device.DeviceInterfaceInstance[]
.EXAMPLE
Get-NtDeviceInterfaceInstance
Get all device interface instances.
.EXAMPLE
Get-NtDeviceInterfaceInstance -Class '6BDD1FC1-810F-11D0-BEC7-08002BE20920'
Get the device interface instances for the specified GUID.
.EXAMPLE
Get-NtDeviceInterfaceInstance -Instance '\\?\HSIDS&1234'
Get the device interface instances for the instance symbolic link path.
#>
function Get-NtDeviceInterfaceInstance {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromClass")]
        [guid]$Class,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromInstance")]
        [string]$Instance
    )

    switch($PSCmdlet.ParameterSetName) {
        "All" {
            [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceInterfaceInstances() | Write-Output
        }
        "FromClass" {
            [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceInterfaceInstances($Class) | Write-Output
        }
        "FromInstance" {
            [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceInterfaceInstance($Instance) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get the NT path for a dos path.
.DESCRIPTION
This cmdlet gets the full NT path for a specified DOS path.
.PARAMETER FullName
The DOS path to convert to NT.
.PARAMETER Resolve
Resolve relative paths to the current PS directory.
.PARAMETER DeviceGuid
Get native path from a Device Interface GUID.
.INPUTS
string[] List of paths to convert.
.OUTPUTS
string Converted path
.EXAMPLE
Get-NtFilePath c:\Windows
Get c:\windows as an NT file path.
.EXAMPLE
Get-ChildItem c:\windows | Get-NtFilePath
Get list of NT file paths from the pipeline.
#>
function Get-NtFilePath {
    [CmdletBinding(DefaultParameterSetName="FromPath")]
    Param(
        [alias("Path")]
        [parameter(Mandatory = $true, Position = 0, ValueFromPipeline, valueFromPipelineByPropertyName, ParameterSetName="FromPath")]
        [string]$FullName,
        [parameter(ParameterSetName="FromPath")]
        [switch]$Resolve,
        [parameter(Mandatory = $true, ParameterSetName="FromGuid")]
        [guid[]]$DeviceGuid
    )

    PROCESS {
        if ($PSCmdlet.ParameterSetName -eq "FromPath") {
            $type = [NtCoreLib.NtFileUtils]::GetDosPathType($FullName)
            $p = $FullName
            if ($Resolve) {
                if ($type -eq "Relative" -or $type -eq "Rooted") {
                    $p = Resolve-Path -LiteralPath $FullName
                }
            }
            try {
                $p = [NtObjectManager.Utils.PSUtils]::ResolveWin32Path($PSCmdlet.SessionState, $p)
                Write-Output $p
            } catch {
                Write-Error $_
            }
        } elseif ($PSCmdlet.ParameterSetName -eq "FromGuid") {
            foreach($g in $DeviceGuid) {
                [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceInterfaceList($g) | Get-NtFilePath | Write-Output
            }
        }
    }
}

<#
.SYNOPSIS
Get the NT path type for a dos path.
.DESCRIPTION
This cmdlet gets the NT path type for a specified DOS path.
.PARAMETER FullName
The DOS path to convert to NT.
.INPUTS
string[] List of paths to convert.
.OUTPUTS
NtCoreLib.RtlPathType
.EXAMPLE
Get-NtFilePathType c:\Windows
Get the path type for c:\windows.
#>
function Get-NtFilePathType {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$FullName
    )

    [NtCoreLib.NtFileUtils]::GetDosPathType($FullName)
}

<#
.SYNOPSIS
Create a new EA buffer object for use with files.
.DESCRIPTION
This cmdlet creates a new extended attributes buffer object to set on file objects with the SetEa method or with New-NtFile.
.PARAMETER Entries
Optional Hashtable containing entries to initialize into the EA buffer.
.PARAMETER $ExistingBuffer
An existing buffer to initialize the new buffer from.
.INPUTS
None
.OUTPUTS
NtCoreLib.Kernel.IO.EaBuffer
.EXAMPLE
New-NtEaBuffer
Create a new empty EaBuffer object
.EXAMPLE
New-NtEaBuffer @{ INTENTRY = 1234; STRENTRY = "ABC"; BYTEENTRY = [byte[]]@(1,2,3) }
Create a new EaBuffer object initialized with three separate entries.
#>
function New-NtEaBuffer {
    [CmdletBinding(DefaultParameterSetName = "FromEntries")]
    Param(
        [Parameter(ParameterSetName = "FromEntries", Position = 0)]
        [Hashtable]$Entries = @{ },
        [Parameter(ParameterSetName = "FromExisting", Position = 0)]
        [NtCoreLib.Kernel.IO.EaBuffer]$ExistingBuffer
    )

    if ($null -eq $ExistingBuffer) {
        $ea_buffer = New-Object NtCoreLib.Kernel.IO.EaBuffer
        foreach ($entry in $Entries.Keys) {
            $ea_buffer.AddEntry($entry, $Entries.Item($entry), 0)
        }
        return $ea_buffer
    }
    else {
        return New-Object NtCoreLib.Kernel.IO.EaBuffer -ArgumentList $ExistingBuffer
    }
}

<#
.SYNOPSIS
Add an entry to an existing EA buffer.
.DESCRIPTION
This cmdlet adds a new extended attributes entry to a buffer.
.PARAMETER Buffer
The EA buffer to add to.
.PARAMETER Byte
The bytes to add.
.PARAMETER Byte
The bytes to add.
.PARAMETER Byte
The bytes to add.
.PARAMETER Byte
The bytes to add.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Add-NtEaBuffer -Buffer $ea -Name "ABC" -Byte @(0, 1, 2, 3)
Add an entry with name ABC and a set of bytes.
.EXAMPLE
Add-NtEaBuffer -Buffer $ea -Name "ABC" -String "Hello"
Add an entry with name ABC and a string.
.EXAMPLE
Add-NtEaBuffer -Buffer $ea -Name "ABC" -Int 1234
Add an entry with name ABC and an integer.
#>
function Add-NtEaBuffer {
    [CmdletBinding(DefaultParameterSetName="FromString")]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Kernel.IO.EaBuffer]$EaBuffer,
        [Parameter(Mandatory, Position = 1)]
        [string]$Name,
        [Parameter(Mandatory, Position = 2, ParameterSetName="FromString")]
        [string]$String,
        [Parameter(Mandatory, Position = 2, ParameterSetName="FromBytes")]
        [byte[]]$Byte,
        [Parameter(Mandatory, ParameterSetName="FromInt")]
        [int]$Int,
        [NtCoreLib.Kernel.IO.EaBufferEntryFlags]$Flags = 0
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromString" {
            $EaBuffer.AddEntry($Name, $String, $Flags)
        }
        "FromBytes" {
            $EaBuffer.AddEntry($Name, $Byte, $Flags)
        }
        "FromInt" {
            $EaBuffer.AddEntry($Name, $Int, $Flags)
        }
    }
}

<#
.SYNOPSIS
Starts a file oplock with a specific level.
.DESCRIPTION
This cmdlet starts a file oplock with a specific level.
.PARAMETER File
The file to oplock on.
.PARAMETER Level
The oplock level to start.
.PARAMETER LeaseLevel
The oplock lease level to start.
.PARAMETER Flags
Flags for the oplock lease.
.PARAMETER Async
Specify to return an asynchronous task which can be waited on with Wait-AsyncTaskResult.
.INPUTS
None
.OUTPUTS
None or NtCoreLib.RequestOplockOutputBuffer if using LeaseLevel. If Async then a Task.
.EXAMPLE
Start-NtFileOplock $file -Exclusive
Start an exclusive oplock.
.EXAMPLE
Start-NtFileOplock $file -Level Level1
Start a level 1 oplock.
.EXAMPLE
Start-NtFileOplock $file -LeaseLevel Read,Handle
Start a "lease" oplock with Read and Handle levels.
#>
function Start-NtFileOplock {
    [CmdletBinding(DefaultParameterSetName = "OplockLevel")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtFile]$File,
        [parameter(Mandatory, ParameterSetName = "OplockExclusive")]
        [switch]$Exclusive,
        [parameter(Mandatory, Position = 1, ParameterSetName = "OplockLevel")]
        [NtCoreLib.OplockRequestLevel]$Level,
        [parameter(Mandatory, ParameterSetName = "OplockLease")]
        [NtCoreLib.OplockLevelCache]$LeaseLevel,
        [parameter(ParameterSetName = "OplockLease")]
        [NtCoreLib.RequestOplockInputFlag]$Flags = "Request",
        [switch]$Async
    )

    $result = switch ($PSCmdlet.ParameterSetName) {
        "OplockExclusive" {
            if ($Async) {
                $File.OplockExclusiveAsync()
            } else {
                $File.OplockExclusive()
            }
        }
        "OplockLevel" {
            if ($Async) {
                $File.RequestOplockAsync($Level)
            } else {
                $File.RequestOplock($Level)
            }
        }
        "OplockLease" {
            if ($Async) {
                $File.RequestOplockLeaseAsync($LeaseLevel, $Flags)
            } else {
                $File.RequestOplockLease($LeaseLevel, $Flags)
            }
        }
    }

    $result | Write-Output
}

<#
.SYNOPSIS
Acknowledges a file oplock break.
.DESCRIPTION
This cmdlet acknowledges a file oplock break with a specific level.
.PARAMETER File
The file to acknowledge the break on.
.PARAMETER Level
The oplock acknowledge level.
.PARAMETER Lease
Acknowledge a lease oplock and reduce level to None.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Confirm-NtFileOplock $file -Level Acknowledge
Acknowledge an oplock break.
.EXAMPLE
Confirm-NtFileOplock $file -LeaseLevel Read
Acknowledge to a read oplock.
#>
function Confirm-NtFileOplock {
    [CmdletBinding(DefaultParameterSetName = "OplockLevel")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtFile]$File,
        [parameter(Mandatory, Position = 1, ParameterSetName = "OplockLevel")]
        [NtCoreLib.OplockAcknowledgeLevel]$Level,
        [parameter(Mandatory, Position = 1, ParameterSetName = "OplockLease")]
        [switch]$Lease,
        [parameter(ParameterSetName = "OplockLease")]
        [switch]$CompleteOnClose
    )

    switch ($PSCmdlet.ParameterSetName) {
        "OplockLevel" {
            $File.AcknowledgeOplock($Level)
        }
        "OplockLease" {
            $File.AcknowledgeOplockLease($CompleteOnClose)
        }
    }
}

<#
.SYNOPSIS
Get the EA buffer from a file.
.DESCRIPTION
This cmdlet queries for the Extended Attribute buffer from a file by path or from a NtFile object.
.PARAMETER Path
NT path to file.
.PARAMETER Win32Path
Specify Path is a Win32 path.
.PARAMETER File
Specify an existing NtFile object.
.INPUTS
None
.OUTPUTS
NtCoreLib.Kernel.IO.EaBuffer
#>
function Get-NtFileEa {
    [CmdletBinding(DefaultParameterSetName = "FromPath")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromPath")]
        [string]$Path,
        [Parameter(ParameterSetName = "FromPath")]
        [switch]$Win32Path,
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromFile")]
        [NtCoreLib.NtFile]$File,
        [switch]$AsEntries
    )

    $ea = switch ($PsCmdlet.ParameterSetName) {
        "FromFile" {
            $File.GetEa()
        }
        "FromPath" {
            Use-NtObject($f = Get-NtFile -Path $Path -Win32Path:$Win32Path -Access ReadEa) {
                $f.GetEa()
            }
        }
    }
    if ($AsEntries) {
        $ea.Entries | Write-Output
    } else {
        $ea | Write-Output
    }
}

<#
.SYNOPSIS
Set the EA buffer on a file.
.DESCRIPTION
This cmdlet sets the Extended Attribute buffer on a file by path or a NtFile object.
.PARAMETER Path
NT path to file.
.PARAMETER Win32Path
Specify Path is a Win32 path.
.PARAMETER File
Specify an existing NtFile object.
.PARAMETER EaBuffer
Specify the EA buffer to set.
.INPUTS
None
.OUTPUTS
None
#>
function Set-NtFileEa {
    [CmdletBinding(DefaultParameterSetName = "FromPath")]
    Param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromPath")]
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromPathAndName")]
        [string]$Path,
        [Parameter(ParameterSetName = "FromPath")]
        [Parameter(ParameterSetName = "FromPathAndName")]
        [switch]$Win32Path,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromFile")]
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromFileAndName")]
        [NtCoreLib.NtFile]$File,
        [Parameter(Mandatory, Position = 1, ParameterSetName = "FromFile")]
        [Parameter(Mandatory, Position = 1, ParameterSetName = "FromPath")]
        [NtCoreLib.Kernel.IO.EaBuffer]$EaBuffer,
        [Parameter(Mandatory, Position = 1, ParameterSetName = "FromPathAndName")]
        [Parameter(Mandatory, Position = 1, ParameterSetName = "FromFileAndName")]
        [string]$Name,
        [Parameter(Mandatory, Position = 2, ParameterSetName = "FromPathAndName")]
        [Parameter(Mandatory, Position = 2, ParameterSetName = "FromFileAndName")]
        [byte[]]$Byte,
        [Parameter(Position = 3, ParameterSetName = "FromPathAndName")]
        [Parameter(Position = 3, ParameterSetName = "FromFileAndName")]
        [NtCoreLib.Kernel.IO.EaBufferEntryFlags]$Flags = 0
    )

    if ($PSCmdlet.ParameterSetName -eq "FromPathAndName" -or $PSCmdlet.ParameterSetName -eq "FromFileAndName") {
        $EaBuffer = New-NtEaBuffer
        Add-NtEaBuffer -EaBuffer $EaBuffer -Name $Name -Byte $Byte -Flags $Flags
    }

    if ($PSCmdlet.ParameterSetName -eq "FromPath" -or $PSCmdlet.ParameterSetName -eq "FromPathAndName") {
        Use-NtObject($f = Get-NtFile -Path $Path -Win32Path:$Win32Path -Access WriteEa) {
            $f.SetEa($EaBuffer)
        }
    } elseif ($PSCmdlet.ParameterSetName -eq "FromFile" -or $PSCmdlet.ParameterSetName -eq "FromFileAndName"){
        $File.SetEa($EaBuffer)
    }
}

<#
.SYNOPSIS
Remove an EA buffer on a file.
.DESCRIPTION
This cmdlet removes an Extended Attribute buffer on a file by path or a NtFile object.
.PARAMETER Path
NT path to file.
.PARAMETER Win32Path
Specify Path is a Win32 path.
.PARAMETER Name
Specify the name of the buffer to remove.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-NtFileEa {
    [CmdletBinding(DefaultParameterSetName = "FromPath")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromPath")]
        [string]$Path,
        [Parameter(ParameterSetName = "FromPath")]
        [switch]$Win32Path,
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromFile")]
        [NtCoreLib.NtFile]$File,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Name
    )

    switch ($PsCmdlet.ParameterSetName) {
        "FromFile" {
            $File.RemoveEa($Name)
        }
        "FromPath" {
            Use-NtObject($f = Get-NtFile -Path $Path -Win32Path:$Win32Path -Access WriteEa) {
                $f.RemoveEa($Name)
            }
        }
    }
}

<#
.SYNOPSIS
Write bytes to a file.
.DESCRIPTION
This cmdlet writes bytes to a file optionally specifying the offset.
.PARAMETER File
Specify the file to write to.
.PARAMETER Bytes
Specify the bytes to write.
.PARAMETER Offset
Specify the offset in the file to write to.
.PARAMETER PassThru
Specify to the return the length written.
.INPUTS
None
.OUTPUTS
int
.EXAMPLE
Write-NtFile -File $f -Bytes @(0, 1, 2, 3)
Write to a file at the current offset.
.EXAMPLE
Write-NtFile -File $f -Bytes @(0, 1, 2, 3) -Offset 1234
Write to a file at offset 1234.
.EXAMPLE
$count = Write-NtFile -File $f -Bytes @(0, 1, 2, 3) -PassThru
Write to a file and return the number of bytes written.
#>
function Write-NtFile {
    [CmdletBinding(DefaultParameterSetName = "NoOffset")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtFile]$File,
        [parameter(Mandatory, Position = 1)]
        [byte[]]$Bytes,
        [parameter(Position = 2, ParameterSetName="UseOffset")]
        [int64]$Offset,
        [switch]$PassThru
    )
    $result = switch($PSCmdlet.ParameterSetName) {
        "NoOffset" {
            $File.Write($Bytes)
        }
        "UseOffset" {
            $File.Write($Bytes, $Offset)
        }
    }

    if ($PassThru) {
        $result | Write-Output
    }
}

<#
.SYNOPSIS
Read bytes from a file.
.DESCRIPTION
This cmdlet writes byte to a file optionally specifying the offset.
.PARAMETER File
Specify the file to read from.
.PARAMETER Length
Specify the number of bytes to read.
.PARAMETER Offset
Specify the offset in the file to read from.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
Read-NtFile -File $f -Length 8
Read 8 bytes from a file at the current offset.
.EXAMPLE
Read-NtFile -File $f -Length 8 -Offset 1234
Read 8 bytes from a file at offset 1234.
#>
function Read-NtFile {
    [CmdletBinding(DefaultParameterSetName = "NoOffset")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtFile]$File,
        [parameter(Mandatory, Position = 1)]
        [int]$Length,
        [parameter(Position = 2, ParameterSetName="UseOffset")]
        [int64]$Offset
    )

    $result = switch($PSCmdlet.ParameterSetName) {
        "NoOffset" {
            $File.Read($Length)
        }
        "UseOffset" {
            $File.Read($Length, $Offset)
        }
    }

    Write-Output $result 
}

<#
.SYNOPSIS
Enumerate file entries for a file directory.
.DESCRIPTION
This cmdlet enumerates directory entries from a file directory.
.PARAMETER File
Specify the file directory to enumerate.
.PARAMETER Pattern
A file pattern to specify the files to enumerate. e.g. *.txt.
.PARAMETER FileType
Specify all files or either files or directories.
.PARAMETER ReparsePoint
Enumerate reparse point information.
.PARAMETER ObjectId
Enumerate object ID information.
.PARAMETER IncludePlaceholder
Include placeholder directories in output.
.PARAMETER FileId
Include file ID in the entries.
.PARAMETER ShortName
Include the short name in the output.
.PARAMETER Path
Path to open the directory first.
.PARAMETER Win32Path
Open a win32 path.
.PARAMETER CaseSensitive
Open the file case sensitively, also does case sensitive pattern matching.
.INPUTS
None
.OUTPUTS
NtCoreLib.Kernel.IO.FileDirectoryEntry[]
NtCoreLib.Kernel.IO.FileIdDirectoryEntry[]
NtCoreLib.Kernel.IO.NtFileReparsePoint[]
NtCoreLib.Kernel.IO.NtFileObjectId[]
.EXAMPLE
Get-NtFileItem -File $f
Enumerate all file items.
.EXAMPLE
Get-NtFileItem -Path \??\c:\windows
Enumerate all file items in c:\windows.
.EXAMPLE
Get-NtFileItem -Path c:\windows -Win32Path
Enumerate all file items in c:\windows.
.EXAMPLE
Get-NtFileItem -File $f -Pattern *.txt
Enumerate all files with a TXT extension.
.EXAMPLE
Get-NtFileItem -File $f -FileType FilesOnly
Enumerate only files.
.EXAMPLE
Get-NtFileItem -File $f -FileType DirectoriesOnly
Enumerate only directories.
.EXAMPLE
Get-NtFileItem -File $f -ReparsePoint
Enumerate reparse points.
.EXAMPLE
Get-NtFileItem -File $f -ObjectId
Enumerate object IDs.
.EXAMPLE
Get-NtFileItem -File $f -FileId
Enumerate files with file ID.
.EXAMPLE
Get-NtFileItem -File $f -ShortName
Enumerate files with short name.
#>
function Get-NtFileItem {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName="Default")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromReparsePoint")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromObjectID")]
        [NtCoreLib.NtFile]$File,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromPath")]
        [string]$Path,
        [parameter(ParameterSetName="FromPath")]
        [switch]$Win32Path,
        [parameter(ParameterSetName="Default")]
        [parameter(ParameterSetName="FromPath")]
        [string]$Pattern = "*",
        [parameter(ParameterSetName="Default")]
        [parameter(ParameterSetName="FromPath")]
        [NtCoreLib.FileTypeMask]$FileType = "All",
        [parameter(ParameterSetName="Default")]
        [parameter(ParameterSetName="FromPath")]
        [switch]$FileId,
        [parameter(ParameterSetName="Default")]
        [parameter(ParameterSetName="FromPath")]
        [switch]$ShortName,
        [parameter(ParameterSetName="Default")]
        [parameter(ParameterSetName="FromPath")]
        [switch]$IncludePlaceholder,
        [parameter(ParameterSetName="FromPath")]
        [switch]$CaseSensitive,
        [parameter(ParameterSetName="FromReparsePoint")]
        [switch]$ReparsePoint,
        [parameter(ParameterSetName="FromObjectID")]
        [switch]$ObjectId
    )

    switch($PSCmdlet.ParameterSetName) {
        "Default" {
            $flags = "Default"
            if ($FileId -and $ShortName) {
                $flags = "FileId, ShortName"
            } elseif($FileId) {
                $flags = "FileId"
            } elseif($ShortName) {
                $flags = "ShortName"
            }

            if ($IncludePlaceholder) {
                $flags += ", Placeholders"
            }
            $File.QueryDirectoryInfo($Pattern, $FileType, $flags) | Write-Output
        }
        "FromPath" {
            $attr = "CaseInsensitive"
            if ($CaseSensitive) {
                $attr = 0
            }
            Use-NtObject($file = Get-NtFile -Path $Path -Win32Path:$Win32Path `
                -DirectoryAccess ListDirectory -ShareMode Read -Options DirectoryFile -AttributeFlags $attr) {
                if ($file -ne $null) {
                    Get-NtFileItem -File $file -Pattern $Pattern -FileType $FileType -FileId:$FileId `
                        -ShortName:$ShortName -IncludePlaceholder:$IncludePlaceholder | Write-Output
                }
            }
        }
        "FromReparsePoint" {
            $File.QueryReparsePoints() | Write-Output
        }
        "FromObjectID" {
            $File.QueryObjectIds() | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get change notification events for a file directory.
.DESCRIPTION
This cmdlet gets change notification envents for a file directory.
.PARAMETER File
Specify the file directory to get change notification events from.
.PARAMETER Filter
Specify what types of events to receive.
.PARAMETER WatchSubtree
Specify to watch all directories in a subtree.
.PARAMETER TimeoutSec
Specify a timeout in seconds to wait if the handle is asynchronous.
.PARAMETER Async
Specify to return an asynchronous task instead of waiting. You can use Wait-AsyncTaskResult
to get the result. The handle must be asynchronous.
.INPUTS
None
.OUTPUTS
NtCoreLib.DirectoryChangeNotification[]
.EXAMPLE
Get-NtFileChange -File $f
Get all change notifications for the file directory.
.EXAMPLE
Get-NtFileChange -File $f -Filter FileName
Get only filename change notifications for the file directory.
.EXAMPLE
Get-NtFileChange -File $f -WatchSubtree
Get all change notifications for the file directory and its children.
.EXAMPLE
Get-NtFileChange -File $f -TimeoutSec 10
Get all change notifications for the file directory, waiting for 10 seconds for a result.
#>
function Get-NtFileChange {
    [CmdletBinding(DefaultParameterSetName = "Sync")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtFile]$File,
        [NtCoreLib.DirectoryChangeNotifyFilter]$Filter = "All",
        [switch]$WatchSubtree,
        [parameter(ParameterSetName="Sync")]
        [int]$TimeoutSec = -1,
        [parameter(Mandatory, ParameterSetName="Async")]
        [switch]$Async
    )

    if ($Async) {
        $File.GetChangeNotificationFullAsync($Filter, $WatchSubtree) | Write-Output
    } else {
        $timeout = Get-NtWaitTimeout -Infinite
        if ($TimeoutSec -ge 0) {
            $timeout = Get-NtWaitTimeout -Second $TimeoutSec
        }
        $File.GetChangeNotificationFull($Filter, $WatchSubtree, $timeout) | Write-Output
    }
}

<#
.SYNOPSIS
Lock a file range.
.DESCRIPTION
This cmdlet locks a file range in an open file.
.PARAMETER File
Specify the file directory to lock.
.PARAMETER Offset
The offset into the file to lock.
.PARAMETER Length
The length of the locked region. 
.PARAMETER All
Specify to lock the entire file.
.PARAMETER Wait
Specify to wait for the lock to be available otherwise fail immediately.
.PARAMETER Exclusive
Specify to create an exclusive lock.
.PARAMETER PassThru
Specify to return a scoped lock which will unlock when disposed.
.INPUTS
None
.OUTPUTS
NtCoreLib.Utilities.IO.NtFileScopedLock
.EXAMPLE
Lock-NtFile -File $f -Offset 0 -Length 256
Lock the first 256 bytes.
.EXAMPLE
Lock-NtFile -File $f -Offset 0 -Length 256 -Wait
Lock the first 256 bytes and wait if already locked.
.EXAMPLE
Lock-NtFile -File $f -All
Lock the entire file.
.EXAMPLE
Lock-NtFile -File $f -All -Exclusive
Lock the entire file exclusively.
#>
function Lock-NtFile {
    [CmdletBinding(DefaultParameterSetName = "FromOffset")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtFile]$File,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromOffset")]
        [int64]$Offset,
        [parameter(Mandatory, Position = 2, ParameterSetName="FromOffset")]
        [int64]$Length,
        [parameter(Mandatory, ParameterSetName="All")]
        [switch]$All,
        [switch]$Wait,
        [switch]$Exclusive,
        [switch]$PassThru
    )

    if ($All) {
        $Offset = 0
        $Length = $File.Length
    }

    if ($PassThru) {
        [NtCoreLib.Utilities.IO.NtFileScopedLock]::Create($File, $Offset, $Length, !$Wait, $Exclusive) | Write-Output
    } else {
        $File.Lock($Offset, $Length, !$Wait, $Exclusive)
    }
}

<#
.SYNOPSIS
Unlock a file range.
.DESCRIPTION
This cmdlet unlocks a file range in an open file.
.PARAMETER File
Specify the file directory to unlock.
.PARAMETER Offset
The offset into the file to unlock.
.PARAMETER Length
The length of the unlocked region. 
.PARAMETER All
Specify to unlock the entire file.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Unlock-NtFile -File $f -Offset 0 -Length 256
Unlock the first 256 bytes.
.EXAMPLE
Unlock-NtFile -File $f -All
Unlock the entire file.
#>
function Unlock-NtFile {
    [CmdletBinding(DefaultParameterSetName = "FromOffset")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtFile]$File,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromOffset")]
        [int64]$Offset,
        [parameter(Mandatory, Position = 2, ParameterSetName="FromOffset")]
        [int64]$Length,
        [parameter(Mandatory, ParameterSetName="All")]
        [switch]$All
    )

    if ($All) {
        $Offset = 0
        $Length = $File.Length
    }

    $File.Unlock($Offset, $Length)
}

<#
.SYNOPSIS
Sets the disposition on a file.
.DESCRIPTION
This cmdlet sets the disposition on a file such as deleting the file.
.PARAMETER File
Specify the file to set.
.PARAMETER Delete
Specify to mark the file as delete on close.
.PARAMETER PosixSemantics
Specify to mark the file as delete on close with POSIX semantics.
.PARAMETER Flags
Specify disposition flags.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-NtFileDisposition -File $f -Delete
Set the file to delete on close.
.EXAMPLE
Set-NtFileDisposition -File $f -Delete:$false
Clear the file delete on close flag.
.EXAMPLE
Set-NtFileDisposition -File $f -Delete -PosixSemantics
Set the file to delete on close with POSIX semantics.
.EXAMPLE
Set-NtFileDisposition -File $f -Flags Delete, IgnoreReadOnlyAttribute
Set the file delete on close flag and ignore the readonly attribute.
#>
function Set-NtFileDisposition {
    [CmdletBinding(DefaultParameterSetName="FromDelete")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtFile]$File,
        [parameter(Mandatory, ParameterSetName="FromDelete")]
        [switch]$Delete,
        [parameter(ParameterSetName="FromDelete")]
        [switch]$PosixSemantics,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromFlags")]
        [NtCoreLib.FileDispositionInformationExFlags]$Flags
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromDelete" {
            if ($PosixSemantics -and $Delete) {
                $File.SetDispositionEx("Delete, PosixSemantics")
            } else {
                $File.SetDisposition($Delete)
            }
        }
        "FromFlags" {
            $File.SetDispositionEx($Flags)
        }
    }
}

<#
.SYNOPSIS
Gets whether the file is being deleted.
.DESCRIPTION
This cmdlet gets whether the file is going to be deleted when closed.
.PARAMETER File
Specify the file to query.
.INPUTS
None
.OUTPUTS
bool
.EXAMPLE
Get-NtFileDisposition -File $f
Get the file to delete on close flag.
#>
function Get-NtFileDisposition {
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtFile]$File
    )
    $File.DeletePending | Write-Output
}

<#
.SYNOPSIS
Generate a 8dot3 name for a full name.
.DESCRIPTION
This cmdlet generates a 8dot3 filename from a full name.
.PARAMETER Name
The name to generate from.
.PARAMETER ExtendedCharacters
Allow extended characters.
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Get-NtFile8dot3Path -Name 0123456789.config 
Generate a 8dot3 name from a full name.
#>
function Get-NtFile8dot3Name {
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [string]$Name,
        [switch]$ExtendedCharacters
    )
    [NtCoreLib.NtFileUtils]::Generate8dot3Name($Name, $ExtendedCharacters) | Write-Output
}

<#
.SYNOPSIS
Tests if a driver is in the device stack of a file.
.DESCRIPTION
This cmdlet checks if a driver is in the device stack of a file.
.PARAMETER File
The file to check. Works with files or direct device opens.
.PARAMETER DriverPath
The object manager path to the driver object. e.g. \Device\volume or just volume.
.INPUTS
None
.OUTPUTS
Bool
.EXAMPLE
Test-NtFileDriverPath -File $f -DriverPath "Ntfs"
Tests if the Ntfs driver is in the path.
#>
function Test-NtFileDriverPath {
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtFile]$File,
        [parameter(Mandatory = $true, Position = 1)]
        [string]$DriverPath
    )
    $File.DriverInPath($DriverPath)
}

<#
.SYNOPSIS
Get list of mount points.
.DESCRIPTION
This cmdlet queries the mount point manager for a list of mount points.
.INPUTS
None
.OUTPUTS
NtCoreLib.IO.MountPointManager.MountPoint[]
.EXAMPLE
Get-NtMountPoint
Get list of mount points.
#>
function Get-NtMountPoint {
    [NtCoreLib.IO.MountPointManager.MountPointManagerUtils]::QueryMountPoints() | Write-Output
}

<#
.SYNOPSIS
Create a new reparse tag buffer.
.DESCRIPTION
This cmdlet creates a new reparse tag buffer.
.PARAMETER Tag
Specify the reparse tag.
.PARAMETER Guid
Specify the GUID for a generic reparse buffer.
.PARAMETER Data
Specify data for the reparse buffer.
.INPUTS
None
.OUTPUTS
NtCoreLib.Kernel.IO.OpaqueReparseBuffer
NtCoreLib.Kernel.IO.GenericReparseBuffer
.EXAMPLE
New-NtFileReparseBuffer -Tag AF_UNIX -Data @(1, 2, 3, 4)
Create a new opaque reparse buffer.
.EXAMPLE
New-NtFileReparseBuffer -GenericTag 100 -Data @(1, 2, 3, 4) -Guid '8b049aa1-e380-4808-aeb4-dffd9d01c0de'
Create a new opaque reparse buffer.
#>
function New-NtFileReparseBuffer {
    [CmdletBinding(DefaultParameterSetName = "OpaqueBuffer")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName="OpaqueBuffer")]
        [NtCoreLib.Kernel.IO.ReparseTag]$Tag,
        [parameter(Mandatory, Position = 0, ParameterSetName="GenericBuffer")]
        [uint32]$GenericTag,
        [parameter(Mandatory, ParameterSetName="GenericBuffer")]
        [guid]$Guid,
        [parameter(Mandatory, Position = 1, ParameterSetName="OpaqueBuffer")]
        [parameter(Mandatory, Position = 1, ParameterSetName="GenericBuffer")]
        [AllowEmptyCollection()]
        [byte[]]$Data
    )

    switch($PSCmdlet.ParameterSetName) {
        "OpaqueBuffer" {
            [NtCoreLib.Kernel.IO.OpaqueReparseBuffer]::new($Tag, $Data) | Write-Output
        }
        "GenericBuffer" {
            [NtCoreLib.Kernel.IO.GenericReparseBuffer]::new($GenericTag, $Guid, $Data) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Query the quota on a volume.
.DESCRIPTION
This cmdlet queries the quote entries on a volume.
.PARAMETER Volume
Specify the name of the volume, e.g. C: or \Device\HarddiskVolumeX
.PARAMETER Sid
Specify a list of sids to query.
.INPUTS
None
.OUTPUTS
NtCoreLib.Kernel.IO.FileQuotaEntry[]
.EXAMPLE
Get-NtFileQuota -Volume C:
Query the quota for the C: volume.
#>
function Get-NtFileQuota {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$Volume,
        [NtCoreLib.Security.Authorization.Sid[]]$Sid
    )
    try {
        if (!$Volume.StartsWith("\")) {
            $Volume = "\??\" + $Volume
        }
        Use-NtObject($vol = Get-NtFile -Path $Volume `
            -Access Execute -Share Read, Write) {
            $vol.QueryQuota($Sid) | Write-Output
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Sets the quota on a volume.
.DESCRIPTION
This cmdlet sets the quote entries on a volume.
.PARAMETER Volume
Specify the name of the volume, e.g. C: or \Device\HarddiskVolumeX
.PARAMETER Sid
Specify the SID to set.
.PARAMETER Limit
Specify the quota limit.
.PARAMETER Threshold
Specify the quota threshold.
.PARAMETER Quota
Specify a list of quota entries.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-NtFileQuota -Volume C: -Sid "S-1-1-0" -Limit (10*1024*1024) -Threshold (8*1024*1024)
Set quota for the Everyone group with a limit of 10MiB and threshold of 8MiB.
.EXAMPLE
Set-NtFileQuota -Volume C: -Quota $qs
Set quota for a list of quota entries.
#>
function Set-NtFileQuota {
    [CmdletBinding(DefaultParameterSetName="FromSid")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$Volume,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromSid")]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [parameter(Mandatory, Position = 2, ParameterSetName="FromSid")]
        [int64]$Limit,
        [parameter(Mandatory, Position = 3, ParameterSetName="FromSid")]
        [int64]$Threshold,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromEntry")]
        [NtCoreLib.Kernel.IO.FileQuotaEntry[]]$Quota
    )
    try {
        if (!$Volume.StartsWith("\")) {
            $Volume = "\??\" + $Volume
        }
        Use-NtObject($vol = Get-NtFile -Path $Volume `
            -Access WriteData -Share Read, Write) {
            if ($PSCmdlet.ParameterSetName -eq "FromSid") {
                $vol.SetQuota($Sid, $Threshold, $Limit)
            } else {
                $vol.SetQuota($Quota)
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Read the USN journal for a volume.
.DESCRIPTION
This cmdlet reads the USN journal reocrds for a volume.
.PARAMETER Volume
Specify the volume to read from.
.PARAMETER StartUsn
Specify the first USN to read from.
.PARAMETER EndUsn
Specify the last USN to read, exclusive.
.PARAMETER ReasonMask
Specify a mask of reason codes to return.
.PARAMETER Unprivileged
Specify to use unprivileged reading. This doesn't return filenames you don't have access to.
.INPUTS
None
.OUTPUTS
NtCoreLib.IO.UsnJournal.UsnJournalRecord[]
.EXAMPLE
Read-NtFileUsnJournal -Volume C:
Read the USN journal for the C: volume.
#>
function Read-NtFileUsnJournal {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$Volume,
        [uint64]$StartUsn = 0,
        [uint64]$EndUsn = [uint64]::MaxValue,
        [NtCoreLib.IO.UsnJournal.UsnJournalReasonFlags]$ReasonMask = "All",
        [switch]$Unprivileged
    )
    try {
        if (!$Volume.StartsWith("\")) {
            $Volume = "\??\" + $Volume
        }

        $Access = "ReadData"

        if ($Unprivileged) {
            $Volume += "\"
            $Access = "Synchronize"
        }

        Use-NtObject($vol = Get-NtFile -Path $Volume `
            -Access $Access -Share Read, Write) {
            if ($Unprivileged) {
                [NtCoreLib.IO.UsnJournal.UsnJournalUtils]::ReadJournalUnprivileged($vol, $StartUsn, $EndUsn, $ReasonMask) | Write-Output
            } else {
                [NtCoreLib.IO.UsnJournal.UsnJournalUtils]::ReadJournal($vol, $StartUsn, $EndUsn, $ReasonMask) | Write-Output
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Gets an IO control code structure.
.DESCRIPTION
This cmdlet gets an IO control code structure from a code or from its constituent parts.
.PARAMETER ControlCode
Specify the control code for the structure.
.PARAMETER DeviceType
Specify the device type component.
.PARAMETER Function
Specify the function code component.
.PARAMETER Method
Specify the control method component.
.PARAMETER Access
Specify the access component.
.PARAMETER LookupName
Specify to try and lookup a known name for the IO control code. If no name found will just return an empty string.
.PARAMETER All
Specify to return all known IO control codes with names.
.PARAMETER Name
Specify to lookup an IO control code with a name.
.PARAMETER AsInt
When looking up by name return the control code as an integer.
.OUTPUTS
NtCoreLib.NtIoControlCode
System.String
.EXAMPLE
Get-NtIoControlCode 0x110028
Get the IO control code structure for a control code.
.EXAMPLE
Get-NtIoControlCode 0x110028 -LookupName
Get the IO control code structure for a control code and lookup its name (if known).
.EXAMPLE
Get-NtIoControlCode -DeviceType NAMED_PIPE -Function 10 -Method Buffered -Access Any
Get the IO control code structure from component parts.
.EXAMPLE
Get-NtIoControlCode -DeviceType NAMED_PIPE -Function 10 -Method Buffered -Access Any -LookupName
Get the IO control code structure from component parts and lookup its name (if known).
.EXAMPLE
Get-NtIoControlCode -Name "FSCTL_GET_REPARSE_POINT"
Get the IO control code structure from a known name.
.EXAMPLE
Get-NtIoControlCode -Name "FSCTL_GET_REPARSE_POINT" -AsInt
Get the IO control code structure from a known name as output an integer.
#>
function Get-NtIoControlCode {
    [CmdletBinding(DefaultParameterSetName = "FromCode")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromCode", Mandatory = $true)]
        [int]$ControlCode,
        [Parameter(ParameterSetName = "FromParts", Mandatory = $true)]
        [NtCoreLib.FileDeviceType]$DeviceType,
        [Parameter(ParameterSetName = "FromParts", Mandatory = $true)]
        [int]$Function,
        [Parameter(ParameterSetName = "FromParts", Mandatory = $true)]
        [NtCoreLib.FileControlMethod]$Method,
        [Parameter(ParameterSetName = "FromParts", Mandatory = $true)]
        [NtCoreLib.FileControlAccess]$Access,
        [Parameter(ParameterSetName = "FromParts")]
        [Parameter(ParameterSetName = "FromCode")]
        [switch]$LookupName,
        [Parameter(ParameterSetName = "FromAll", Mandatory = $true)]
        [switch]$All,
        [Parameter(ParameterSetName = "FromName", Mandatory = $true)]
        [string]$Name,
        [Parameter(ParameterSetName = "FromParts")]
        [Parameter(ParameterSetName = "FromName")]
        [switch]$AsInt
    )
    $result = switch ($PsCmdlet.ParameterSetName) {
        "FromCode" {
            [NtCoreLib.NtIoControlCode]::new($ControlCode)
        }
        "FromParts" {
            [NtCoreLib.NtIoControlCode]::new($DeviceType, $Function, $Method, $Access)
        }
        "FromAll" {
            [NtCoreLib.NtWellKnownIoControlCodes]::GetKnownControlCodes()
        }
        "FromName" {
            [NtCoreLib.NtWellKnownIoControlCodes]::GetKnownControlCodeByName($Name)
        }
    }

    if ($LookupName) {
        return [NtCoreLib.NtWellKnownIoControlCodes]::KnownControlCodeToName($result)
    }

    if ($AsInt) {
        $result.ToInt32() | Write-Output
    } else {
        $result | Write-Output
    }
}

<#
.SYNOPSIS
Gets a list of system environment values
.DESCRIPTION
This cmdlet gets the list of system environment values. Note that this isn't the same as environment
variables, these are kernel values which represent current system state.
.PARAMETER Name
The name of the system environment value to get.
.INPUTS
None
#>
function Get-NtSystemEnvironmentValue {
    Param(
        [Parameter(Position = 0)]
        [string]$Name = [System.Management.Automation.Language.NullString]::Value
    )
    Set-NtTokenPrivilege SeSystemEnvironmentPrivilege | Out-Null
    $values = [NtCoreLib.NtSystemInfo]::QuerySystemEnvironmentValueNamesAndValues()
    if ($Name -eq [string]::Empty) {
        $values
    }
    else {
        $values | Where-Object Name -eq $Name
    }
}

<#
.SYNOPSIS
Get a license value by name.
.DESCRIPTION
This cmdlet gets a license value by name
.PARAMETER Name
The name of the license value to get.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtKeyValue
#>
function Get-NtLicenseValue {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Name
    )
    [NtCoreLib.NtKey]::QueryLicenseValue($Name)
}

<#
.SYNOPSIS
Get the values from a registry key.
.DESCRIPTION
This cmdlet will get one or more values from a registry key.
.PARAMETER Key
The base key to query the values from.
.PARAMETER Name
The name of the value to query. If not specified then returns all values.
.PARAMETER AsString
Output the values as strings.
.PARAMETER AsObject
Output the values as the data object.
.INPUTS
None
.OUTPUTS
NtKeyValue
.EXAMPLE
Get-NtKeyValue -Key $key
Get all values from a key.
.EXAMPLE
Get-NtKeyValue -Key $key -AsString
Get all values from a key as a string.
.EXAMPLE
Get-NtKeyValue -Key $key -Name ""
Get the default value from a key.
.EXAMPLE
Get-NtKeyValue -Key $key -Name MyValue
Get the MyValue value from a key.
#>
function Get-NtKeyValue {
    [CmdletBinding(DefaultParameterSetName = "FromKeyAll")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName="FromKeyAll")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromKeyName")]
        [NtCoreLib.NtKey]$Key,
        [parameter(ParameterSetName = "FromKeyName", Mandatory, Position = 1)]
        [parameter(ParameterSetName = "FromPathName", Mandatory, Position = 1)]
        [string]$Name,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromPathAll")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromPathName")]
        [string]$Path,
        [parameter(ParameterSetName = "FromPathAll")]
        [parameter(ParameterSetName = "FromPathName")]
        [switch]$Win32Path,
        [switch]$AsString,
        [switch]$AsObject
    )

    try {
        $values = switch ($PSCmdlet.ParameterSetName) {
            "FromKeyAll" {
                $Key.QueryValues()
            }
            "FromKeyName" {
                @($Key.QueryValue($Name))
            }
            "FromPathName" {
                Use-NtObject($k = Get-NtKey -Path $Path -Win32Path:$Win32Path -Access QueryValue) {
                    @($k.QueryValue($Name))
                }
            }
            "FromPathAll" {
                Use-NtObject($k = Get-NtKey -Path $Path -Win32Path:$Win32Path -Access QueryValue) {
                    $k.QueryValues()
                }
            }
        }
        if ($AsString) {
            $values | ForEach-Object { $_.ToString() } | Write-Output
        } elseif($AsObject) {
            $values | ForEach-Object { $_.ToObject() } | Write-Output
        } else {
            $values | Write-Output
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Remove a value from a registry key.
.DESCRIPTION
This cmdlet will remove one more values from a registry key.
.PARAMETER Key
The base key to remove the values from.
.PARAMETER Name
The names of the values to remove.
.INPUTS
None
.EXAMPLE
Remove-NtKeyValue -Key $key -Name ABC
Removes the value ABC from the Key.
.EXAMPLE
Remove-NtKeyValue -Key $key -Name ABC, XYZ
Removes the value ABC and XYZ from the Key.
#>
function Remove-NtKeyValue {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtKey]$Key,
        [parameter(Mandatory, Position = 1)]
        [string[]]$Name
    )
    foreach ($n in $Name) {
        $Key.DeleteValue($n)
    }
}

<#
.SYNOPSIS
Gets the list of loaded hives.
.DESCRIPTION
This cmdlet enumerates the list of loaded hives from the Registry.
.PARAMETER FormatWin32File
Format the file path to a Win32 string if possible.
.INPUTS
None
.OUTPUTS
NtKeyHive[]
.EXAMPLE
Get-NtKeyHiveSplit
Get the list of loaded hives.
.EXAMPLE
Get-NtKeyHiveSplit -FormatWin32File
Get the list of loaded hives with the file path in Win32 format.
#>
function Get-NtKeyHive {
    Param(
        [switch]$FormatWin32File
    )
    [NtCoreLib.NtKeyUtils]::GetHiveList($FormatWin32File) | Write-Output
}

<#
.SYNOPSIS
Backup a key to a file.
.DESCRIPTION
This cmdlet back ups a key to a file.
.PARAMETER Path
The path to the file to backup to.
.PARAMETER Win32Path
The path is a Win32 path.
.PARAMETER File
Specify the file to write to.
.PARAMETER Key
The key to backup.
.PARAMETER Flags
Flags for the backup operation.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Backup-NtKey -Key $key -Path \??\c:\backup.hiv
Backup the key to c:\backup.hiv
.EXAMPLE
Backup-NtKey -Key $key -Path backup.hiv -Win32Path
Backup the key to backup.hiv in the current directory.
.EXAMPLE
Backup-NtKey -Key $key -File $file
Backup the key to a file object.
#>
function Backup-NtKey {
    [CmdletBinding(DefaultParameterSetName = "FromPath")]
    Param(
        [parameter(Position = 0, Mandatory)]
        [NtCoreLib.NtKey]$Key,
        [NtCoreLib.SaveKeyFlags]$Flags = "StandardFormat",
        [parameter(Position = 1, Mandatory, ParameterSetName="FromPath")]
        [string]$Path,
        [parameter(ParameterSetName="FromPath")]
        [switch]$Win32Path,
        [parameter(Position = 1, Mandatory, ParameterSetName="FromFile")]
        [NtCoreLib.NtFile]$File
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromFile" {
            $Key.Save($File, $Flags)
        }
        "FromPath" {
            if ($Win32Path) {
                $Path = Get-NtFilePath -FullName $Path
            }
            $Key.Save($Path, $Flags)
        }
    }
}

<#
.SYNOPSIS
Restore a key from a file.
.DESCRIPTION
This cmdlet restores a key from a file.
.PARAMETER Path
The path to the file to restore from.
.PARAMETER Win32Path
The path is a Win32 path.
.PARAMETER File
Specify the file to read from.
.PARAMETER Key
The key to restore.
.PARAMETER Flags
Flags for the restore operation.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Restore-NtKey -Key $key -Path \??\c:\backup.hiv
Restore the key from c:\backup.hiv
.EXAMPLE
Restore-NtKey -Key $key -Path backup.hiv -Win32Path
Restore the key from backup.hiv in the current directory.
.EXAMPLE
Restore-NtKey -Key $key -File $file
Restore the key from a file object.
#>
function Restore-NtKey {
    [CmdletBinding(DefaultParameterSetName = "FromPath")]
    Param(
        [parameter(Position = 0, Mandatory)]
        [NtCoreLib.NtKey]$Key,
        [NtCoreLib.RestoreKeyFlags]$Flags = "None",
        [parameter(Position = 1, Mandatory, ParameterSetName="FromPath")]
        [string]$Path,
        [parameter(ParameterSetName="FromPath")]
        [switch]$Win32Path,
        [parameter(Position = 1, Mandatory, ParameterSetName="FromFile")]
        [NtCoreLib.NtFile]$File
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromFile" {
            $Key.Restore($File, $Flags)
        }
        "FromPath" {
            if ($Win32Path) {
                $Path = Get-NtFilePath -FullName $Path
            }
            $Key.Restore($Path, $Flags)
        }
    }
}

<#
.SYNOPSIS
Export details about an object to re-import in another process.
.DESCRIPTION
This function generates a short JSON string which can be used to duplicate into another process
using the Import-NtObject function. The handle must be valid when the import function is executed.
.PARAMETER Object
Specify the object to export.
.OUTPUTS
string
.EXAMPLE
Export-NtObject $obj
Export an object to a JSON string.
#>
function Export-NtObject {
    param(
        [Parameter(Position = 0, Mandatory = $true)]
        [NtCoreLib.NtObject]$Object
    )
    $obj = [PSCustomObject]@{ProcessId = $PID; Handle = $Object.Handle.DangerousGetHandle().ToInt32() }
    $obj | ConvertTo-Json -Compress
}

<#
.SYNOPSIS
Imports an object exported with Export-NtObject.
.DESCRIPTION
This function accepts a JSON string exported from Export-NtObject which allows an object to be
duplicated between PowerShell instances. You can also specify the PID and handle separetly.
.PARAMETER Object
Specify the object to import as a JSON string.
.PARAMETER ProcessId
Specify the process ID to import from.
.PARAMETER Handle
Specify the handle value to import from.
.OUTPUTS
NtCoreLib.NtObject (the best available type).
.EXAMPLE
Import-NtObject '{"ProcessId":3300,"Handle":2660}'
Import an object from a JSON string.
.EXAMPLE
Import-NtObject -ProcessId 3300 -Handle 2660
Import an object from separate PID and handle values.
#>
function Import-NtObject {
    [CmdletBinding(DefaultParameterSetName = "FromObject")]
    param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromObject")]
        [string]$Object,
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromPid")]
        [int]$ProcessId,
        [Parameter(Position = 1, Mandatory, ParameterSetName = "FromPid")]
        [int]$Handle
    )
    switch ($PSCmdlet.ParameterSetName) {
        "FromObject" {
            $obj = ConvertFrom-Json $Object
            Import-NtObject -ProcessId $obj.ProcessId -Handle $obj.Handle
        }
        "FromPid" {
            Use-NtObject($generic = [NtCoreLib.NtGeneric]::DuplicateFrom($ProcessId, $Handle)) {
                $generic.ToTypedObject()
            }
        }
    }
}

<#
.SYNOPSIS
Resolve the address of a list of objects.
.DESCRIPTION
This cmdlet resolves the kernel address for a list of objects. This is an expensive operation so it's designed to be
called with a list.
.PARAMETER Objects
The list of objects to resolve.
.PARAMETER PassThru
Write the object addresses to the object. Normally no output is generated.
.OUTPUTS
Int64 - If PassThru specified.
.EXAMPLE
Resolve-NtObjectAddress $obj1, $obj2; $obj1.Address
Resolve the address of two objects.
#>
function Resolve-NtObjectAddress {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [NtCoreLib.NtObject[]]$Objects,
        [switch]$PassThru
    )
    BEGIN {
        $objs = @()
    }
    PROCESS {
        $objs += $Objects
    }
    END {
        [NtCoreLib.NtSystemInfo]::ResolveObjectAddress([NtCoreLib.NtObject[]]$objs)
        if ($PassThru) {
            $objs | Select-Object -ExpandProperty Address | Write-Output
        }
    }
}

<#
.SYNOPSIS
Gets an object from a handle in the current process.
.DESCRIPTION
This cmdlet creates an object for a handle in the current process.
.PARAMETER Handle
Specify the handle in the current process.
.PARAMETER OwnsHandle
Specify the own the handle (closed when object is disposed).
.INPUTS
None
.OUTPUTS
NtCoreLib.NtObject
.EXAMPLE
Get-NtObjectFromHandle -Handle 0x1234
Get an object from handle 0x1234.
.EXAMPLE
Get-NtObjectFromHandle -Handle 0x1234 -OwnsHandle
Get an object from handle 0x1234 and owns the handle.
#>
function Get-NtObjectFromHandle {
    Param(
        [parameter(Mandatory, Position = 0)]
        [IntPtr]$Handle,
        [switch]$OwnsHandle
    )

    $temp_handle = [NtCoreLib.Native.SafeHandles.SafeKernelObjectHandle]::new($Handle, $false)
    [NtCoreLib.NtType]::GetTypeForHandle($temp_handle, $true).FromHandle($Handle, $OwnsHandle)
}

<#
.SYNOPSIS
Close an object handle.
.DESCRIPTION
This cmdlet closes an object handle. It supports closing a handle locally or in another process as long
as duplicate handle access is granted.
.PARAMETER Object
Specify the object to close.
.PARAMETER Process
Specify the process where the handle to close is located.
.PARAMETER ProcessId
Specify the process ID where the handle to close is located.
.PARAMETER Handle
Specify the handle value to close in another process.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Close-NtObject -Object $obj
Close an object in the current process.
.EXAMPLE
Close-NtObject -Handle 0x1234 -Process $proc
Close handle 0x1234 in another process.
.EXAMPLE
Close-NtObject -Handle 0x1234 -ProcessId 684
Close handle 0x1234 in process with ID 684.
.EXAMPLE
Close-NtObject -Handle 0x1234
Close handle 0x1234 in process the current process.
#>
function Close-NtObject {
    [CmdletBinding(DefaultParameterSetName = "FromProcess")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromObject", ValueFromPipeline)]
        [NtCoreLib.NtObject]$Object,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromProcess")]
        [NtCoreLib.NtProcess]$Process,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromProcessId")]
        [int]$ProcessId,
        [parameter(Mandatory, Position = 1, ParameterSetName = "FromProcess")]
        [parameter(Mandatory, Position = 1, ParameterSetName = "FromProcessId")]
        [parameter(Mandatory, Position = 1, ParameterSetName = "FromCurrentProcess")]
        [IntPtr]$Handle,
        [parameter(Mandatory, ParameterSetName = "FromCurrentProcess")]
        [parameter(Mandatory, ParameterSetName = "FromCurrentProcessSafe")]
        [switch]$CurrentProcess,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromCurrentProcessSafe")]
        [NtCoreLib.Native.SafeHandles.SafeKernelObjectHandle]$SafeHandle
    )

    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "FromObject" { $Object.Close() }
            "FromProcess" { [NtCoreLib.NtObject]::CloseHandle($Process, $Handle) }
            "FromProcessId" { [NtCoreLib.NtObject]::CloseHandle($ProcessId, $Handle) }
            "FromCurrentProcess" { [NtCoreLib.NtObject]::CloseHandle($Handle) }
            "FromCurrentProcessSafe" { [NtCoreLib.NtObject]::CloseHandle($SafeHandle) }
        }
    }
}

<#
.SYNOPSIS
Gets the information classes for a type.
.DESCRIPTION
This cmdlet gets the list of information classes for a type. You can get the query and set information classes.
.PARAMETER Type
The NT type to get information classes for.
.PARAMETER Object
The object to get information classes for.
.PARAMETER Set
Specify to get the set information classes which might differ.
.PARAMETER Volume
Specify to get the volume information classes.
.INPUTS
None
.OUTPUTS
KeyPair<string, int>[]
#>
function Get-NtObjectInformationClass {
    [CmdletBinding(DefaultParameterSetName = "FromType")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromType")]
        [NtCoreLib.NtType]$Type,
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromObject")]
        [NtCoreLib.NtObject]$Object,
        [Parameter(ParameterSetName = "FromObject")]
        [Parameter(ParameterSetName = "FromType")]
        [switch]$Set,
        [Parameter(ParameterSetName = "FromVolume")]
        [switch]$Volume
    )

    if ($Volume) {
        [NtObjectManager.Utils.PSUtils]::GetFsVolumeInfoClass() | Write-Output
    } else {
        if ($PSCmdlet.ParameterSetName -eq "FromObject") {
            $Type = $Object.NtType
        }

        if ($Set) {
            $Type.SetInformationClass | Write-Output
        }
        else {
            $Type.QueryInformationClass | Write-Output
        }
    }
}

<#
.SYNOPSIS
Compares two object handles to see if they're the same underlying object.
.DESCRIPTION
This cmdlet compares two handles to see if they're the same underlying object.
On Window 10 this is a supported operation, for downlevel queries the address for
the objects and compares that instead.
.PARAMETER Left
The left hand object to compare.
.PARAMETER Right
The right hand object to compare.
.INPUTS
None
.OUTPUTS
bool
#>
function Compare-NtObject {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.NtObject]$Left,
        [Parameter(Position = 1, Mandatory)]
        [NtCoreLib.NtObject]$Right
    )
    $Left.SameObject($Right) | Write-Output
}

<#
.SYNOPSIS
Test if an object can be opened.
.DESCRIPTION
This cmdlet tests if an object exists by opening it. This might give false negatives
if the reason for not opening it was unrelated to it not existing.
.PARAMETER Path
Specify an object path to get the security descriptor from.
.PARAMETER TypeName
Specify the type name of the object at Path. Needed if the module cannot automatically determine the NT type to open.
.PARAMETER Root
Specify a root object for Path.
.INPUTS
None
.OUTPUTS
Boolean
.EXAMPLE
Test-NtObject \BaseNamedObjects\ABC
Test if \BaseNamedObjects\ABC can be opened.
.EXAMPLE
Test-NtObject ABC -Root $dir
Test if ABC can be opened relative to $dir.
.EXAMPLE
Test-NtObject \BaseNamedObjects\ABC -TypeName Mutant.
Test if \BaseNamedObjects\ABC can be opened with a File type.
#>
function Test-NtObject {
    [CmdletBinding(DefaultParameterSetName = "FromPath")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromPath")]
        [string]$Path,
        [parameter(ParameterSetName = "FromPath")]
        [string]$TypeName,
        [parameter(ParameterSetName = "FromPath")]
        [NtCoreLib.NtObject]$Root
    )
    switch ($PsCmdlet.ParameterSetName) {
        "FromPath" {
            try {
                Use-NtObject($obj = Get-NtObject -Path $Path -Root $Root -TypeName $TypeName) { }
                return $true
            } 
            catch {
                return $false
            }
        }
    }
}

<#
.SYNOPSIS
Create a new object attributes structure.
.DESCRIPTION
This cmdlet creates a new object attributes structure based on its parameters. Note you should dispose of the object
attributes afterwards.
.PARAMETER Name
Optional NT native name for the object
.PARAMETER Root
Optional NT object root for relative paths
.PARAMETER Attributes
Optional object attributes flags
.PARAMETER SecurityQualityOfService
Optional security quality of service flags
.PARAMETER SecurityDescriptor
Optional security descriptor
.PARAMETER Sddl
Optional security descriptor in SDDL format
.INPUTS
None
.EXAMPLE
New-NtObjectAttributes \??\c:\windows
Create a new object attributes for \??\C:\windows
#>
function New-NtObjectAttributes {
    Param(
        [Parameter(Position = 0)]
        [string]$Name,
        [NtCoreLib.NtObject]$Root,
        [NtCoreLib.AttributeFlags]$Attributes = "None",
        [NtCoreLib.Security.Token.SecurityQualityOfService]$SecurityQualityOfService,
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [string]$Sddl
    )

    $sd = $SecurityDescriptor
    if ($Sddl -ne "") {
        $sd = New-NtSecurityDescriptor -Sddl $Sddl
    }

    [NtCoreLib.ObjectAttributes]::new($Name, $Attributes, [NtCoreLib.NtObject]$Root, $SecurityQualityOfService, $sd)
}

<#
.SYNOPSIS
Create a new native NT process configuration.
.DESCRIPTION
This cmdlet creates a new native process configuration which you can then pass to New-NtProcess.
.PARAMETER ImagePath
The path to image file to load.
.PARAMETER CommandLine
The command line of the process to create.
.PARAMETER ProcessFlags
Flags to affect process creation.
.PARAMETER ThreadFlags
Flags to affect thread creation.
.PARAMETER ProtectedType
Protected process type.
.PARAMETER ProtectedSigner
Protected process signer.
.PARAMETER TerminateOnDispose
Specify switch to terminate the process when the CreateUserProcessResult object is disposed.
.PARAMETER ProhibitedImageCharacteristics
Specify prohibited image characteristics for the new process.
.PARAMETER ChildProcessMitigations
Specify child process mitigations.
.PARAMETER AdditionalFileAccess
Specify additional file access mask.
.PARAMETER InitFlags
Specify additional initialization flags.
.PARAMETER Win32Path
Specify ImagePath is a Win32 path.
.PARAMETER CaptureAdditionalInformation
Specify to capture additional information from create call.
.PARAMETER Secure
Specify to create a secure process.
.INPUTS
None
.OUTPUTS
NtCoreLib.Process.Kernel.NtProcessCreateConfig
#>
function New-NtProcessConfig {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$ImagePath,
        [Parameter(Position = 1)]
        [string]$CommandLine,
        [NtCoreLib.ProcessCreateFlags]$ProcessFlags = 0,
        [NtCoreLib.ThreadCreateFlags]$ThreadFlags = 0,
        [NtCoreLib.PsProtectedType]$ProtectedType = 0,
        [NtCoreLib.PsProtectedSigner]$ProtectedSigner = 0,
        [NtCoreLib.ImageCharacteristics]$ProhibitedImageCharacteristics = 0,
        [NtCoreLib.ChildProcessMitigationFlags]$ChildProcessMitigations = 0,
        [NtCoreLib.FileAccessRights]$AdditionalFileAccess = 0,
        [NtCoreLib.ProcessCreateInitFlag]$InitFlags = 0,
        [switch]$TerminateOnDispose,
        [switch]$Win32Path,
        [switch]$CaptureAdditionalInformation,
        [switch]$Secure,
        [NtCoreLib.NtObject[]]$InheritHandle
    )

    if ($Win32Path) {
        $ImagePath = Get-NtFilePath $ImagePath -Resolve
    }

    if ("" -eq $CommandLine) {
        $CommandLine = $ImagePath
    }

    $config = New-Object NtCoreLib.Process.Kernel.NtProcessCreateConfig
    $config.ImagePath = $ImagePath
    $config.ProcessFlags = $ProcessFlags
    $config.ThreadFlags = $ThreadFlags
    $config.CommandLine = $CommandLine
    $config.ProhibitedImageCharacteristics = $ProhibitedImageCharacteristics
    $config.ChildProcessMitigations = $ChildProcessMitigations
    $config.AdditionalFileAccess = $AdditionalFileAccess
    $config.InitFlags = $InitFlags
    $config.TerminateOnDispose = $TerminateOnDispose
    if ($ProtectedType -ne 0 -or $ProtectedSigner -ne 0) {
        $config.AddProtectionLevel($ProtectedType, $ProtectedSigner)
        $config.ProcessFlags = $ProcessFlags -bor "ProtectedProcess"
    }
    $config.CaptureAdditionalInformation = $CaptureAdditionalInformation
    $config.Secure = $Secure
    if ($null -ne $InheritHandle) {
        $config.InheritHandleList.AddRange($InheritHandle)
    }

    return $config
}

<#
.SYNOPSIS
Create a new native NT process.
.DESCRIPTION
This cmdlet creates a new native NT process. This can be via NtCreateUserProcess with a configuration
or NtCreateProcessEx without configuration.
.PARAMETER Config
The configuration for the new process from New-NtProcessConfig.
.PARAMETER ReturnOnError
Specify to always return a result even on error.
.PARAMETER SecurityDescriptor
Specify security descriptor for the process.
.PARAMETER Access
Specify the access to the process object.
.PARAMETER Parent
Specify the parent process. Default is current process.
.PARAMETER Flags
Specify creation flags.
.PARAMETER Section
Specify initial image section.
.PARAMETER DebugPort
Specify debug port.
.PARAMETER Token
Specify process token.
.INPUTS
None
.OUTPUTS
NtCoreLib.Process.Kernel.NtProcessCreateResult
NtCoreLib.NtProcess
#>
function New-NtProcess {
    [CmdletBinding(DefaultParameterSetName="FromCreateEx")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName="FromConfig")]
        [NtCoreLib.Process.Kernel.NtProcessCreateConfig]$Config,
        [Parameter(ParameterSetName="FromConfig")]
        [switch]$ReturnOnError,
        [Parameter(ParameterSetName="FromCreateEx")]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(ParameterSetName="FromCreateEx")]
        [NtCoreLib.ProcessAccessRights]$Access = "MaximumAllowed",
        [Parameter(ParameterSetName="FromCreateEx")]
        [NtCoreLib.NtProcess]$Parent,
        [Parameter(ParameterSetName="FromCreateEx")]
        [NtCoreLib.ProcessCreateFlags]$Flags = 0,
        [Parameter(ParameterSetName="FromCreateEx")]
        [NtCoreLib.NtSection]$Section,
        [Parameter(ParameterSetName="FromCreateEx")]
        [NtCoreLib.NtDebug]$DebugPort,
        [Parameter(ParameterSetName="FromCreateEx")]
        [NtCoreLib.NtToken]$Token
    )

    if ($PSCmdlet.ParameterSetName -eq "FromConfig") {
        [NtCoreLib.NtProcess]::Create($Config, !$ReturnOnError)
    } else {
        Use-NtObject($obja = New-NtObjectAttributes -SecurityDescriptor $SecurityDescriptor) {
            [NtCoreLib.NtProcess]::Create($obja, $Access, $Parent, $Flags, $Section, $DebugPort, $Token)
        }
    }
}

<#
.SYNOPSIS
Get security mitigations and token security information for processes.
.DESCRIPTION
This cmdlet will get the mitigation policies for processes it can access. The default is to return mitigations for all accessible processes.
.PARAMETER Name
The name of the processes to get mitigations for.
.PARAMETER ProcessId
One or more process IDs to get mitigations for.
.PARAMETER PageFlags
Optional flags to control what additional pages to dump
.INPUTS
None
.EXAMPLE
Get-NtProcessMitigations
Get all accessible process mitigations.
.EXAMPLE
Get-NtProcessMitigations -Name MicrosoftEdgeCP.exe
Get process mitigations for Edge content processes.
.EXAMPLE
Get-NtProcessMitigations -ProcessId 1234, 4568
Get process mitigations for two processes by ID.
#>
function Get-NtProcessMitigations {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(ParameterSetName = "FromName", Position = 0, Mandatory)]
        [string]$Name,
        [parameter(ParameterSetName = "FromProcessId", Position = 0, Mandatory)]
        [int[]]$ProcessId,
        [parameter(ParameterSetName = "FromProcess")]
        [NtCoreLib.NtProcess[]]$Process
    )
    Set-NtTokenPrivilege SeDebugPrivilege | Out-Null
    $ps = switch ($PSCmdlet.ParameterSetName) {
        "All" {
            Get-NtProcess -Access QueryInformation
        }
        "FromName" {
            Get-NtProcess -Name $Name
        }
        "FromProcessId" {
            foreach ($id in $ProcessId) {
                Get-NtProcess -ProcessId $id
            }
        }
        "FromProcess" {
            Copy-NtObject -Object $Process
        }
    }
    Use-NtObject($ps) {
        foreach ($p in $ps) {
            try {
                Write-Output $p.Mitigations
            }
            catch {
                Write-Error $_
            }
        }
    }
}

<#
.SYNOPSIS
Get a specified mitigation policy value for a process.
.DESCRIPTION
This cmdlet queries for a specific mitigation policy value from a process. The result is an enumeration or a raw value depending on the request.
.PARAMETER Process
Specify the process to query. Defaults to the current process.
.PARAMETER Policy
Specify the mitigation policy.
.PARAMETER AsRaw
Specify the query the policy as a raw integer.
.INPUTS
None
.OUTPUTS
An enumerated value or an integer.
.EXAMPLE
Get-NtProcessMitigationPolicy Signature
Query the signature mitigation policy for the current process.
.EXAMPLE
Get-NtProcessMitigationPolicy Signature -Process $p
Query the signature mitigation policy for a specified process.
.EXAMPLE
Get-NtProcessMitigationPolicy Signature -Process-AsRaw
Query the signature mitigation policy for the current process as a raw integer.
#>
function Get-NtProcessMitigationPolicy {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.ProcessMitigationPolicy]$Policy,
        [parameter(ValueFromPipeline)]
        [NtCoreLib.NtProcess]$Process,
        [switch]$AsRaw
    )

    PROCESS {
        if ($null -eq $Process) {
            $Process = Get-NtProcess -Current
        }
        if ($AsRaw) {
            $Process.GetRawMitigationPolicy($Policy) | Write-Output
        }
        else {
            $Process.GetMitigationPolicy($Policy) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Set a specified mitigation policy value for a process.
.DESCRIPTION
This cmdlet sets a specific mitigation policy value for a process. The policy value can either be an explicit enumeration or a raw value.
.PARAMETER Process
Specify the process to set. Defaults to the current process and the majority of policies can't be set externally.
.PARAMETER Policy
Specify the mitigation policy when setting a raw value.
.PARAMETER RawValue
Specify the raw value to set.
.PARAMETER ImageLoad,
Specify policy flags for image load mitigation.
.PARAMETER Signature,
Specify policy flags for signature mitigation policy.
.PARAMETER SystemCallDisable,
Specify policy flags for system call disable mitigation policy.
.PARAMETER DynamicCode,
Specify policy flags for dynamic code mitigation policy.
.PARAMETER ExtensionPointDisable,
Specify policy flags for extension point disable mitigation policy.
.PARAMETER FontDisable,
Specify policy flags for font disable mitigation policy.
.PARAMETER ControlFlowGuard,
Specify policy flags for control flow guard mitigation policy.
.PARAMETER StrictHandleCheck,
Specify policy flags for strict handle check mitigation policy.
.PARAMETER ChildProcess,
Specify policy flags for child process mitigation policy.
.PARAMETER PayloadRestriction,
Specify policy flags for payload restrictions mitigation policy.
.PARAMETER SystemCallFilter,
Specify policy flags for system call filter mitigation policy.
.PARAMETER SideChannelIsolation,
Specify policy flags for side channel isolation mitigation policy.
.PARAMETER Aslr
Specify policy flags for ASLR mitigation policy.
.PARAMETER RedirectionTrust
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-NtProcessMitigationPolicy -Policy Signature -RawValue 1
Set the signature mitigation policy for the current process with a raw value of 1.
.EXAMPLE
Set-NtProcessMitigationPolicy -Signature MicrosoftSignedOnly
Set mitigation signed only signature policy for the current process.
.EXAMPLE
Set-NtProcessMitigationPolicy -Signature MicrosoftSignedOnly -Process $p
Set mitigation signed only signature policy for a specified process.
#>
function Set-NtProcessMitigationPolicy {
    [CmdletBinding()]
    Param(
        [parameter(ValueFromPipeline)]
        [NtCoreLib.NtProcess]$Process,
        [parameter(Mandatory, ParameterSetName = "FromRaw")]
        [int]$RawValue,
        [parameter(Mandatory, ParameterSetName = "FromRaw")]
        [NtCoreLib.ProcessMitigationPolicy]$Policy,
        [parameter(Mandatory, ParameterSetName = "FromImageLoad")]
        [NtCoreLib.ProcessMitigationImageLoadPolicy]$ImageLoad,
        [parameter(Mandatory, ParameterSetName = "FromSignature")]
        [NtCoreLib.ProcessMitigationBinarySignaturePolicy]$Signature,
        [parameter(Mandatory, ParameterSetName = "FromSystemCallDisable")]
        [NtCoreLib.ProcessMitigationSystemCallDisablePolicy]$SystemCallDisable,
        [parameter(Mandatory, ParameterSetName = "FromDynamicCode")]
        [NtCoreLib.ProcessMitigationDynamicCodePolicy]$DynamicCode,
        [parameter(Mandatory, ParameterSetName = "FromExtensionPointDisable")]
        [NtCoreLib.ProcessMitigationExtensionPointDisablePolicy]$ExtensionPointDisable,
        [parameter(Mandatory, ParameterSetName = "FromFontDisable")]
        [NtCoreLib.ProcessMitigationFontDisablePolicy]$FontDisable,
        [parameter(Mandatory, ParameterSetName = "FromControlFlowGuard")]
        [NtCoreLib.ProcessMitigationControlFlowGuardPolicy]$ControlFlowGuard,
        [parameter(Mandatory, ParameterSetName = "FromStrictHandleCheck")]
        [NtCoreLib.ProcessMitigationStrictHandleCheckPolicy]$StrictHandleCheck,
        [parameter(Mandatory, ParameterSetName = "FromChildProcess")]
        [NtCoreLib.ProcessMitigationChildProcessPolicy]$ChildProcess,
        [parameter(Mandatory, ParameterSetName = "FromPayloadRestriction")]
        [NtCoreLib.ProcessMitigationPayloadRestrictionPolicy]$PayloadRestriction,
        [parameter(Mandatory, ParameterSetName = "FromSystemCallFilter")]
        [NtCoreLib.ProcessMitigationSystemCallFilterPolicy]$SystemCallFilter,
        [parameter(Mandatory, ParameterSetName = "FromSideChannelIsolation")]
        [NtCoreLib.ProcessMitigationSideChannelIsolationPolicy]$SideChannelIsolation,
        [parameter(Mandatory, ParameterSetName = "FromAslr")]
        [NtCoreLib.ProcessMitigationAslrPolicy]$Aslr,
        [parameter(Mandatory, ParameterSetName = "FromRedirectionTrust")]
        [NtCoreLib.ProcessMitigationRedirectionTrustPolicy]$RedirectionTrust
    )

    BEGIN {
        $Value = 0
        $FromRaw = $false
        switch ($PsCmdlet.ParameterSetName) {
            "FromRaw" { $Value = $RawValue; $FromRaw = $true }
            "FromImageLoad" { $Policy = "ImageLoad"; $Value = $ImageLoad }
            "FromSignature" { $Policy = "Signature"; $Value = $Signature }
            "FromSystemCallDisable" { $Policy = "SystemCallDisable"; $Value = $SystemCallDisable }
            "FromDynamicCode" { $Policy = "DynamicCode"; $Value = $DynamicCode }
            "FromExtensionPointDisable" { $Policy = "ExtensionPointDisable"; $Value = $ExtensionPointDisable }
            "FromFontDisable" { $Policy = "FontDisable"; $Value = $FontDisable }
            "FromControlFlowGuard" { $Policy = "ControlFlowGuard"; $Value = $ControlFlowGuard }
            "FromStrictHandleCheck" { $Policy = "StrictHandleCheck"; $Value = $StrictHandleCheck }
            "FromChildProcess" { $Policy = "ChildProcess"; $Value = $ChildProcess }
            "FromPayloadRestriction" { $Policy = "PayloadRestriction"; $Value = $PayloadRestriction }
            "FromSystemCallFilter" { $Policy = "SystemCallFilter"; $Value = $SystemCallFilter }
            "FromSideChannelIsolation" { $Policy = "SideChannelIsolation"; $Value = $SideChannelIsolation }
            "FromAslr" { $Policy = "ASLR"; $Value = $Aslr }
            "FromRedirectionTrust" { $Policy = "RedirectionTrust"; $Value = $RedirectionTrust }
        }
    }

    PROCESS {
        if ($null -eq $Process) {
            $Process = Get-NtProcess -Current
        }

        if ($FromRaw) {
            $Process.SetRawMitigationPolicy($Policy, $Value)
        }
        else {
            $Process.SetMitigationPolicy($Policy, $Value)
        }
    }
}

<#
.SYNOPSIS
Suspend a process.
.DESCRIPTION
This cmdlet suspends a process.
.PARAMETER Process
The process to suspend.
.INPUTS
NtCoreLib.NtProcess
.OUTPUTS
None
#>
function Suspend-NtProcess {
    [CmdletBinding(DefaultParameterSetName = "FromProcess")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromProcess", ValueFromPipeline)]
        [NtCoreLib.NtProcess[]]$Process
    )

    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "FromProcess" {
                foreach ($p in $Process) {
                    $p.Suspend()
                }
            }
        }
    }
}

<#
.SYNOPSIS
Resume a process.
.DESCRIPTION
This cmdlet resumes a process.
.PARAMETER Process
The process to resume.
.INPUTS
NtCoreLib.NtProcess
.OUTPUTS
None
#>
function Resume-NtProcess {
    [CmdletBinding(DefaultParameterSetName = "FromProcess")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromProcess", ValueFromPipeline)]
        [NtCoreLib.NtProcess[]]$Process
    )

    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "FromProcess" {
                foreach ($p in $Process) {
                    $p.Resume()
                }
            }
        }
    }
}

<#
.SYNOPSIS
Stop a process.
.DESCRIPTION
This cmdlet stops/kills a process with an optional status code.
.PARAMETER Process
The process to stop.
.PARAMETER ExitCode
The NTSTATUS exit code.
.PARAMETER ExitCodeInt
The exit code as an integer.
.INPUTS
NtCoreLib.NtProcess
.OUTPUTS
None
#>
function Stop-NtProcess {
    [CmdletBinding(DefaultParameterSetName = "FromStatus")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]
        [NtCoreLib.NtProcess[]]$Process,
        [Parameter(Position = 1, ParameterSetName = "FromStatus")]
        [NtCoreLib.NtStatus]$ExitStatus = 0,
        [Parameter(Position = 1, ParameterSetName = "FromInt")]
        [int]$ExitCode = 0
    )

    PROCESS {
        foreach ($p in $Process) {
            switch ($PsCmdlet.ParameterSetName) {
                "FromStatus" { $p.Terminate($ExitStatus) }
                "FromInt" { $p.Terminate($ExitCode) }
            }
        }
    }
}

<#
.SYNOPSIS
Get user SID for a process.
.DESCRIPTION
This cmdlet will get the user SID for a process.
.PARAMETER Process
The process object.
.PARAMETER ProcessId
The PID of the process.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.Sid
.EXAMPLE
Get-NtProcessUser -ProcessId 1234
Get user SID for process ID 1234.
.EXAMPLE
Get-NtProcessUser -Process $p
Get user SID for process.
#>
function Get-NtProcessUser {
    [CmdletBinding(DefaultParameterSetName = "FromProcessId")]
    Param(
        [parameter(ParameterSetName = "FromProcessId", Position = 0, Mandatory)]
        [alias("pid")]
        [int]$ProcessId,
        [parameter(ParameterSetName = "FromProcess", Mandatory)]
        [NtCoreLib.NtProcess]$Process
    )
    switch ($PSCmdlet.ParameterSetName) {
        "FromProcessId" {
            Set-NtTokenPrivilege -Privilege SeDebugPrivilege -WarningAction SilentlyContinue
            Use-NtObject($p = Get-NtProcess -ProcessId $ProcessId -Access QueryLimitedInformation) {
                Get-NtProcessUser -Process $p | Write-Output
            }
        }
        "FromProcess" {
            $Process.User | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get environment variables from a process.
.DESCRIPTION
This cmdlet will get the environment variables from a process.
.PARAMETER Process
The process object.
.PARAMETER ProcessId
The process ID.
.PARAMETER Name
The name of the variable.
.INPUTS
None
.OUTPUTS
NtCoreLib.Kernel.Process.NtProcessEnvironmentVariable[]
.EXAMPLE
Get-NtProcessEnvironment -ProcessId 1234
Get environment for process 1234.
.EXAMPLE
Get-NtProcessEnvironment -Process $p
Get environment for process.
.EXAMPLE
Get-NtProcessEnvironment -ProcessId 1234 -Name "TMP"
Get environment variable TMP for process 1234.
#>
function Get-NtProcessEnvironment {
    [CmdletBinding(DefaultParameterSetName = "FromProcessId")]
    Param(
        [parameter(ParameterSetName = "FromProcessId", Position = 0, Mandatory)]
        [alias("pid")]
        [int]$ProcessId,
        [parameter(ParameterSetName = "FromProcess", Mandatory)]
        [NtCoreLib.NtProcess]$Process,
        [string]$Name
    )

    switch ($PSCmdlet.ParameterSetName) {
        "FromProcessId" {
            Set-NtTokenPrivilege -Privilege SeDebugPrivilege -WarningAction SilentlyContinue
            Use-NtObject($p = Get-NtProcess -ProcessId $ProcessId -Access VmRead, QueryLimitedInformation) {
                if ($Name -ne "") {
                    $p.GetEnvironmentVariable($Name) | Write-Output
                } else {
                    $p.GetEnvironment() | Write-Output
                }
            }
        }
        "FromProcess" {
            if ($Name -ne "") {
                $Process.GetEnvironmentVariable($Name) | Write-Output
            } else {
                $Process.GetEnvironment() | Write-Output
            }
        }
    }
}

<#
.SYNOPSIS
Checks if the process is in a Job or a specific Job.
.DESCRIPTION
This cmdlet checks if a process is in any Job or a specific Job.
.PARAMETER Process
Specify the process to check.
.PARAMETER Job
Specify a Job object to check. If not specified then will check for any Job.
.PARAMETER Current
Specify to check the current process.
.INPUTS
None
.OUTPUTS
Bool
.EXAMPLE
Test-NtProcessJob -Process $proc
Test if the process is a job.
.EXAMPLE
Test-NtProcessJob -Process $proc -Job $job
Test if the process is in a specific job.
.EXAMPLE
Test-NtProcessJob -Current
Test if the current process is a job.
.EXAMPLE
Test-NtProcessJob -Current -Job $job
Test if the current process is in a specific job.
#>
function Test-NtProcessJob {
    [CmdletBinding(DefaultParameterSetName="FromProcess")]
    param(
        [parameter(Mandatory, Position = 0, ParameterSetName="FromProcess")]
        [NtCoreLib.NtProcess]$Process,
        [parameter(Position = 1)]
        [NtCoreLib.NtJob]$Job,
        [parameter(Mandatory, ParameterSetName="FromCurrent")]
        [switch]$Current
    )
    if ($Current) {
        $Process = Get-NtProcess -Current
    }
    $Process.IsInJob($Job)
}

<#
.SYNOPSIS
Test if a process can be opened.
.DESCRIPTION
This cmdlet tests if a process can be opened. You can specify a specific access mask to check
or request the maximum access.
.PARAMETER ProcessId
Specify the process ID to check.
.PARAMETER Access
Specify the access to check.
.INPUTS
None
.OUTPUTS
Boolean
.EXAMPLE
Test-NtProcess -ProcessId 1234
Test if PID 1234 can be opened with maximum access.
.EXAMPLE
Test-NtProcess -ProcessId 1234 -Access DupHandle
Test if PID 1234 can be opened with DupHandle access.
#>
function Test-NtProcess {
    [CmdletBinding()]
    param (
        [alias("pid")]
        [parameter(Mandatory, Position = 0)]
        [int]$ProcessId,
        [NtCoreLib.ProcessAccessRights]$Access = "MaximumAllowed"
    )

    Use-NtObject($proc = [NtCoreLib.NtProcess]::Open($ProcessId, $Access, $false)) {
        $proc.IsSuccess
    }
}

<#
.SYNOPSIS
Create a new image section based on an existing file.
.DESCRIPTION
This cmdlet creates an image section based on an existing file.
.PARAMETER File
A file object to an image file to create.
.PARAMETER Path
A path to an image to create.
.PARAMETER Win32Path
Resolve path as a Win32 path
.PARAMETER ObjectPath
Specify an object path for the new section object.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtSection
.EXAMPLE
New-NtSectionImage -Path \??\c:\windows\notepad.exe
Creates a
.EXAMPLE
New-NtSectionImage -File $file
Creates a new image section from an open NtFile object.
#>
function New-NtSectionImage {
    [CmdletBinding(DefaultParameterSetName = "FromFile")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromFile", Mandatory = $true)]
        [NtCoreLib.NtFile]$File,
        [Parameter(Position = 0, ParameterSetName = "FromPath", Mandatory = $true)]
        [string]$Path,
        [Parameter(ParameterSetName = "FromPath")]
        [switch]$Win32Path,
        [string]$ObjectPath
    )

    if ($null -eq $File) {
        if ($Win32Path) {
            $Path = Get-NtFilePath $Path -Resolve
        }
        Use-NtObject($new_file = Get-NtFile -Path $Path -Share Read, Delete -Access GenericExecute) {
            return [NtCoreLib.NtSection]::CreateImageSection($ObjectPath, $new_file)
        }
    }
    else {
        return [NtCoreLib.NtSection]::CreateImageSection($ObjectPath, $File)
    }
}

<#
.SYNOPSIS
Displays a mapped section in a UI.
.DESCRIPTION
This cmdlet displays a section object inside a UI from where the data can be inspected or edited.
.PARAMETER Section
Specify a section object.
.PARAMETER Wait
Optionally wait for the user to close the UI.
.PARAMETER ReadOnly
Optionally force the viewer to be read-only when passing a section with Map Write access.
.PARAMETER Path
Path to a file to view as a section.
.PARAMETER ObjPath
Path to a object name to view as a section.
.OUTPUTS
None
.EXAMPLE
Show-NtSection $section
Show the mapped section.
.EXAMPLE
Show-NtSection $section -ReadOnly
Show the mapped section as read only.
.EXAMPLE
Show-NtSection $section -Wait
Show the mapped section and wait for the viewer to exit.
.EXAMPLE
Show-NtSection ([byte[]]@(0, 1, 2, 3))
Show an arbitrary byte array in the viewer.
.EXAMPLE
Show-NtSection path\to\file.bin
Show an arbitrary file in the viewer.
#>
function Show-NtSection {
    [CmdletBinding(DefaultParameterSetName = "FromSection")]
    Param(
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "FromSection")]
        [NtCoreLib.NtSection]$Section,
        [Parameter(ParameterSetName = "FromSection")]
        [switch]$ReadOnly,
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "FromData")]
        [byte[]]$Data,
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "FromFile")]
        [string]$Path,
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "FromPath")]
        [string]$ObjPath,
        [switch]$Wait
    )
    switch ($PSCmdlet.ParameterSetName) {
        "FromSection" {
            if (!$Section.IsAccessGranted("MapRead")) {
                Write-Error "Section doesn't have Map Read access."
                return
            }
            Use-NtObject($obj = $Section.Duplicate()) {
                $cmdline = [string]::Format("EditSection --handle {0}", $obj.Handle.DangerousGetHandle())
                if ($ReadOnly) {
                    $cmdline += " --readonly"
                }
                [NtObjectManager.Utils.PSUtils]::StartUtilityProcess("$PSScriptRoot\EditSection.exe", $cmdline, $Wait, $obj)
            }
        }
        "FromData" {
            if ($Data.Length -eq 0) {
                return
            }
            $tempfile = New-TemporaryFile
            $path = $tempfile.FullName
            [System.IO.File]::WriteAllBytes($path, $Data)

            [NtObjectManager.Utils.PSUtils]::StartUtilityProcess("$PSScriptRoot\EditSection.exe", "EditSection --delete --file=""$path""", $Wait)
        }
        "FromFile" {
            $Path = Resolve-Path $Path
            if ($Path -ne "") {
                [NtObjectManager.Utils.PSUtils]::StartUtilityProcess("$PSScriptRoot\EditSection.exe", "EditSection --file=""$Path""", $Wait)
            }
        }
        "FromPath" {
            [NtObjectManager.Utils.PSUtils]::StartUtilityProcess("$PSScriptRoot\EditSection.exe", "EditSection --path=""$ObjPath""", $Wait)
        }
    }
}

<#
.SYNOPSIS
Get a mapped view of a section.
.DESCRIPTION
This cmdlet calls the Map method on a section to map it into memory.
.PARAMETER Section
The section object to map.
.PARAMETER Protection
The protection of the mapping.
.PARAMETER Process
Optional process to map the section into. Default is the current process.
.PARAMETER ViewSize
The size of the view to map, 0 means map the entire section.
.PARAMETER BaseAddress
Base address for the mapping, 0 means pick a location.
.PARAMETER ZeroBits
The number of zero bits in the mapping address.
.PARAMETER CommitSize
The size of memory to commit from the section.
.PARAMETER SectionOffset
Offset into the section for the base address.
.PARAMETER SectionInherit
Inheritance flags for the section.
.PARAMETER AllocationType
The allocation type for the mapping.
.OUTPUTS
NtCoreLib.NtMappedSection - The mapped section.
.EXAMPLE
Add-NtSection -Section $sect -Protection ReadWrite
Map the section as Read/Write.
.EXAMPLE
Add-NtSection -Section $sect -Protection ReadWrite -ViewSize 4096
Map the first 4096 bytes of the section as Read/Write.
.EXAMPLE
Add-NtSection -Section $sect -Protection ReadWrite -SectionOffset (64*1024)
Map the section starting from offset 64k.
#>
function Add-NtSection {
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtSection]$Section,
        [parameter(Mandatory, Position = 1)]
        [NtCoreLib.MemoryAllocationProtect]$Protection,
        [NtCoreLib.NtProcess]$Process,
        [IntPtr]$ViewSize = 0,
        [IntPtr]$BaseAddress = 0,
        [IntPtr]$ZeroBits = 0,
        [IntPtr]$CommitSize = 0,
        [NtCoreLib.LargeInteger]$SectionOffset,
        [NtCoreLib.SectionInherit]$SectionInherit = [NtCoreLib.SectionInherit]::ViewUnmap,
        [NtCoreLib.AllocationType]$AllocationType = "None"
    )

    if ($null -eq $Process) {
        $Process = Get-NtProcess -Current
    }

    $Section.Map($Process, $Protection, $ViewSize, $BaseAddress, `
            $ZeroBits, $CommitSize, $SectionOffset, `
            $SectionInherit, $AllocationType) | Write-Output
}

<#
.SYNOPSIS
Unmap a view of a section.
.DESCRIPTION
This cmdlet unmaps a section from virtual memory.
.PARAMETER Mapping
The mapping to unmap.
.PARAMETER Address
The address to unmap.
.PARAMETER Process
Optional process to unmap from. Default is the current process.
.PARAMETER Flags
Optional flags for unmapping.
.OUTPUTS
None
.EXAMPLE
Remove-NtSection -Mapping $map
Unmap an existing section created with Add-NtSection.
.EXAMPLE
Remove-NtSection -Address $addr
Unmap an address
.EXAMPLE
Remove-NtSection -Address $addr -Process $p
Unmap an address in a specified process.
#>
function Remove-NtSection {
    [CmdletBinding(DefaultParameterSetName = "FromMapping")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromMapping")]
        [NtCoreLib.NtMappedSection]$Mapping,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromAddress")]
        [int64]$Address,
        [parameter(Position = 1, ParameterSetName = "FromAddress")]
        [NtCoreLib.NtProcess]$Process,
        [parameter(ParameterSetName = "FromAddress")]
        [NtCoreLib.MemUnmapFlags]$Flags = 0
    )

    switch ($PsCmdlet.ParameterSetName) {
        "FromMapping" { $Mapping.Dispose() }
        "FromAddress" {
            if ($null -eq $Process) {
                $Process = Get-NtProcess -Current
            }

            $Process.Unmap($Address, $Flags)
        }
    }
}

<#
.SYNOPSIS
Get the cached signing level for a file.
.DESCRIPTION
This cmdlet gets the cached signing level for a specified file.
.PARAMETER Path
The file to get the cached signing level from.
.PARAMETER Win32Path
Specify to treat Path as a Win32 path.
.PARAMETER FromEa
Specify whether to the read the cached signing level from the extended attribute.
.OUTPUTS
NtCoreLib.Security.CodeIntegrity.CachedSigningLevel
.EXAMPLE
Get-NtCachedSigningLevel \??\c:\path\to\file.dll
Get the cached signing level from \??\c:\path\to\file.dll
.EXAMPLE
Get-NtCachedSigningLevel c:\path\to\file.dll -Win32Path
Get the cached signing level from c:\path\to\file.dll converting from a win32 path.
.EXAMPLE
Get-NtCachedSigningLevel \??\c:\path\to\file.dll -FromEa
Get the cached signing level from \??\c:\path\to\file.dll using the extended attribute.
#>
function Get-NtCachedSigningLevel {
    Param(
        [parameter(Position = 0, Mandatory)]
        [string]$Path,
        [switch]$Win32Path,
        [switch]$FromEa
    )

    $access = if ($FromEa) {
        [NtCoreLib.FileAccessRights]::ReadEa
    }
    else {
        [NtCoreLib.FileAccessRights]::ReadData
    }

    Use-NtObject($f = Get-NtFile $Path -Win32Path:$Win32Path -Access $access -ShareMode Read) {
        if ($FromEa) {
            $f.GetCachedSigningLevelFromEa();
        }
        else {
            $f.GetCachedSigningLevel()
        }
    }
}

<#
.SYNOPSIS
Set the cached signing level for a file.
.DESCRIPTION
This cmdlet sets the cached signing level for a specified file.
.PARAMETER Path
The file to set the cached signing level on.
.PARAMETER Win32Path
Specify to treat Path as a Win32 path.
.PARAMETER Flags
Specify the flags for the cache operation.
.PARAMETER SigningLevel
Specify the signing level for the cache operation.
.PARAMETER AdditionalFiles
Specify the additional files for the cache operation.
.PARAMETER CatalogPath
Specify the catalog path for the cache operation.
.PARAMETER PassThru
Specify to return the cached signing level.
INPUTS
None
.OUTPUTS
NtCoreLib.Security.CodeIntegrity.CachedSigningLevel
.EXAMPLE
Set-NtCachedSigningLevel \??\c:\path\to\file.dll
Set the cached signing level to \??\c:\path\to\file.dll
.EXAMPLE
Set-NtCachedSigningLevel c:\path\to\file.dll -Win32Path
Set the cached signing level to \??\c:\path\to\file.dll
#>
function Set-NtCachedSigningLevel {
    Param(
        [parameter(Position = 0, Mandatory)]
        [string]$Path,
        [switch]$Win32Path,
        [int]$Flags = 4,
        [NtCoreLib.Security.CodeIntegrity.SigningLevel]$SigningLevel = 0,
        [NtCoreLib.NtFile[]]$AdditionalFiles,
        [string]$CatalogPath,
        [switch]$PassThru
    )

    Use-NtObject($f = Get-NtFile $Path -Win32Path:$Win32Path -Access ReadData -ShareMode Read, Delete) {
        $f.SetCachedSigningLevel($Flags, $SigningLevel, $AdditionalFiles, $CatalogPath)
        if ($PassThru) {
            $f.GetCachedSigningLevel()
        }
    }
}

<#
.SYNOPSIS
Gets the signing level for an image file.
.DESCRIPTION
This cmdlet gets the signing level for an image file.
.PARAMETER Path
Specify the path to the image file.
.PARAMETER Win32Path
Specify that the path is a Win32 path.
.PARAMETER DontResolve
Specify to not try and resolve the signing level.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.CodeIntegrity.SigningLevel
#>
function Get-NtSigningLevel {
    [CmdletBinding(DefaultParameterSetName="FromPath")]
    param(
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromPath")]
        [string]$Path,
        [Parameter(ParameterSetName="FromPath")]
        [switch]$Win32Path,
        [switch]$DontResolve
    )

    try {
        if ($Win32Path) {
            $Path = Get-NtFilePath -Path $Path
        }

        Use-NtObject($sect = New-NtSectionImage -Path $Path) {
            Use-NtObject($map = $sect.MapRead()) {
                if ($map.ImageSigningLevel -ne "Unchecked" -or $DontResolve) {
                    return $map.ImageSigningLevel
                }

                $script = { 
                    Set-NtProcessMitigationPolicy -Signature AuditMicrosoftSignedOnly
                    [NtObjectManager.Utils.PSUtils]::GetSigningLevel($input) | Out-Null
                }

                $job = Start-Job -ScriptBlock $script -InputObject $Path
                Wait-Job $job | Out-Null

                return $map.ImageSigningLevel
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Compares two signing levels to see which is higher.
.DESCRIPTION
This cmdlet compares two signing levels to see which is higher.
.PARAMETER
.INPUTS
None
.OUTPUTS
Bool
.EXAMPLE
Compare-NtSigningLevel -Left Windows -Right WindowsTCB
Compare two signing levels, returns True if the left level is greater or equal to right.
#>
function Compare-NtSigningLevel {
    param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Security.CodeIntegrity.SigningLevel]$Left,
        [parameter(Mandatory, Position = 1)]
        [NtCoreLib.Security.CodeIntegrity.SigningLevel]$Right
    )
    [NtCoreLib.Security.NtSecurity]::CompareSigningLevel($Left, $Right)
}

<#
.SYNOPSIS
Shows an object's security descriptor in a UI.
.DESCRIPTION
This cmdlet displays the security descriptor for an object in the standard Windows UI. If an object is passed
and the handle grants WriteDac access then the viewer will also allows you to modify the security descriptor.
.PARAMETER Object
Specify an object to use for the security descriptor.
.PARAMETER SecurityDescriptor
Specify a security descriptor.
.PARAMETER Type
Specify the NT object type for the security descriptor.
.PARAMETER Name
Optional name to display with the security descriptor.
.PARAMETER Wait
Optionally wait for the user to close the UI.
.PARAMETER ReadOnly
Optionally force the viewer to be read-only when passing an object with WriteDac access.
.PARAMETER Container
Specify the SD is a container.
.OUTPUTS
None
.EXAMPLE
Show-NtSecurityDescriptor $obj
Show the security descriptor of an object.
.EXAMPLE
Show-NtSecurityDescriptor $obj -ReadOnly
Show the security descriptor of an object as read only.
.EXAMPLE
Show-NtSecurityDescriptor $obj.SecurityDescriptor -Type $obj.NtType
Show the security descriptor for an object via it's properties.
#>
function Show-NtSecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName = "FromObject")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromObject", Mandatory = $true)]
        [NtCoreLib.Security.Authorization.INtObjectSecurity]$Object,
        [Parameter(ParameterSetName = "FromObject")]
        [switch]$ReadOnly,
        [Parameter(Position = 0, ParameterSetName = "FromAccessCheck", Mandatory = $true)]
        [NtObjectManager.Cmdlets.Accessible.CommonAccessCheckResult]$AccessCheckResult,
        [Parameter(Position = 0, ParameterSetName = "FromSecurityDescriptor", Mandatory = $true)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, ParameterSetName = "FromSecurityDescriptor")]
        [NtCoreLib.NtType]$Type,
        [Parameter(ParameterSetName = "FromSecurityDescriptor")]
        [string]$Name = "Object",
        [Parameter(ParameterSetName = "FromSecurityDescriptor")]
        [switch]$Container,
        [switch]$Wait
    )

    switch ($PsCmdlet.ParameterSetName) {
        "FromObject" {
            if (!$Object.IsAccessMaskGranted([NtCoreLib.GenericAccessRights]::ReadControl)) {
                Write-Error "Object doesn't have Read Control access."
                return
            }
            # If an ALPC Port or not an NtObject pass as an SD.
            if (($Object.NtType.Name -eq "ALPC Port" ) -or !($Object -is [NtCoreLib.NtObject])) {
                Show-NtSecurityDescriptor $Object.SecurityDescriptor $Object.NtType -Name $Object.ObjectName -Wait:$Wait
                return
            }
            Use-NtObject($obj = $Object.Duplicate()) {
                $cmdline = "ViewSecurityDescriptor {0}" -f $obj.Handle.DangerousGetHandle()
                if ($ReadOnly) {
                    $cmdline += " --readonly"
                }
                [NtObjectManager.Utils.PSUtils]::StartUtilityProcess("$PSScriptRoot\ViewSecurityDescriptor.exe", $cmdline, $Wait, $obj)
            }
        }
        "FromSecurityDescriptor" {
            if ($Type -eq $null) {
                $Type = $SecurityDescriptor.NtType
            }

            if ($null -eq $Type) {
                Write-Warning "Defaulting NT type to File. This might give incorrect results."
                $Type = Get-NtType File
            }
            if (-not $Container) {
                $Container = $SecurityDescriptor.Container
            }

            $sd = [Convert]::ToBase64String($SecurityDescriptor.ToByteArray())
            $cmdline = "ViewSecurityDescriptor `"$Name`" -$sd `"$($Type.Name)`" $Container"
            [NtObjectManager.Utils.PSUtils]::StartUtilityProcess("$PSScriptRoot\ViewSecurityDescriptor.exe", $cmdline, $Wait)
        }
        "FromAccessCheck" {
            if ($AccessCheckResult.SecurityDescriptorBase64 -eq "") {
                return
            }

            $sd = New-NtSecurityDescriptor -Base64 $AccessCheckResult.SecurityDescriptorBase64
            Show-NtSecurityDescriptor -SecurityDescriptor $sd `
                -Type $AccessCheckResult.TypeName -Name $AccessCheckResult.Name
        }
    }
}

<#
.SYNOPSIS
Create a new security quality of service structure.
.DESCRIPTION
This cmdlet creates a new security quality of service structure structure based on its parameters
.PARAMETER ImpersonationLevel
The impersonation level, must be specified.
.PARAMETER ContextTrackingMode
Optional tracking mode, defaults to static tracking
.PARAMETER EffectiveOnly
Optional flag to specify if only the effective rights should be impersonated
.INPUTS
None
OUTPUTS
NtCoreLib.Security.Token.SecurityQualityOfService
#>
function New-NtSecurityQualityOfService {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [NtCoreLib.Security.Token.SecurityImpersonationLevel]$ImpersonationLevel,
        [NtCoreLib.Security.Token.SecurityContextTrackingMode]$ContextTrackingMode = "Static",
        [switch]$EffectiveOnly
    )

    [NtCoreLib.Security.Token.SecurityQualityOfService]::new($ImpersonationLevel, $ContextTrackingMode, $EffectiveOnly)
}

function Format-NtAce {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline)]
        [NtCoreLib.Security.Authorization.Ace]$Ace,
        [Parameter(Position = 1, Mandatory = $true)]
        [NtCoreLib.NtType]$Type,
        [switch]$MapGeneric,
        [switch]$Summary,
        [switch]$Container,
        [switch]$SDKName,
        [switch]$ResolveObjectType,
        [string]$Domain
    )

    PROCESS {
        $mask = $ace.Mask
        $access_name = "Access"
        $mask_str = if ($ace.Type -eq "MandatoryLabel") {
            [NtCoreLib.Security.NtSecurity]::AccessMaskToString($mask.ToMandatoryLabelPolicy(), $SDKName)
            $access_name = "Policy"
        }
        else {
            $Type.AccessMaskToString($Container, $mask, $MapGeneric, $SDKName)
        }

        if ($SDKName) {
            $ace_type = [NtCoreLib.Security.NtSecurity]::AceTypeToSDKName($ace.Type)
            $ace_flags = [NtCoreLib.Security.NtSecurity]::AceFlagsToSDKName($ace.Flags)
        } else {
            $ace_type = $ace.Type
            $ace_flags = $ace.Flags
        }

        if ($Summary) {
            $cond = ""
            if ($ace.IsCompoundAce) {
                $cond += "(Server:$($ace.ServerSID.Name))"
            }
            if ($ace.IsConditionalAce) {
                $cond = "($($ace.Condition))"
            }
            if ($ace.IsResourceAttributeAce) {
                $cond = "($($ace.ResourceAttribute.ToSddl()))"
            }
            if ($ace.IsObjectAce) {
                if ($null -ne $ace.ObjectType) {
                    $name = $ace.ObjectType
                    if ($ResolveObjectType) {
                        $name = $ace.GetObjectTypeName($Domain, $false)
                    }
                    $cond += "(OBJ:$name)"
                }
                if ($null -ne $ace.InheritedObjectType) {
                    $name = $ace.InheritedObjectType
                    if ($ResolveObjectType) {
                        $name = $ace.GetInheritedObjectTypeName($Domain)
                    }
                    $cond += "(IOBJ:$name)"
                }
            }

            Write-Output "$($ace.Sid.Name): ($ace_type)($ace_flags)($mask_str)$cond"
        }
        else {
            Write-Output " - Type  : $ace_type"
            Write-Output " - Name  : $($ace.Sid.Name)"
            Write-Output " - SID   : $($ace.Sid)"
            if ($ace.IsCompoundAce) {
                Write-Output " - ServerName: $($ace.ServerSid.Name)"
                Write-Output " - ServerSID : $($ace.ServerSid)"
            }
            Write-Output " - Mask  : 0x$($mask.ToString("X08"))"
            Write-Output " - $($access_name): $mask_str"
            Write-Output " - Flags : $ace_flags"
            if ($ace.IsConditionalAce) {
                Write-Output " - Condition: $($ace.Condition)"
            }
            if ($ace.IsResourceAttributeAce) {
                Write-Output " - Attribute: $($ace.ResourceAttribute.ToSddl())"
            }
            if ($ace.IsObjectAce) {
                if ($null -ne $ace.ObjectType) {
                    $name = $ace.ObjectType
                    if ($ResolveObjectType) {
                        $name = $ace.GetObjectTypeName($Domain, $false)
                    }
                    Write-Output " - ObjectType: $name"
                }
                if ($null -ne $ace.InheritedObjectType) {
                    $name = $ace.InheritedObjectType
                    if ($ResolveObjectType) {
                        $name = $ace.GetInheritedObjectTypeName($Domain)
                    }
                    Write-Output " - InheritedObjectType: $name"
                }
            }
            Write-Output ""
        }
    }
}

function Format-NtAcl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [AllowEmptyCollection()]
        [NtCoreLib.Security.Authorization.Acl]$Acl,
        [Parameter(Position = 1, Mandatory)]
        [NtCoreLib.NtType]$Type,
        [Parameter(Position = 2, Mandatory)]
        [string]$Name,
        [switch]$MapGeneric,
        [switch]$AuditOnly,
        [switch]$Summary,
        [switch]$Container,
        [switch]$SDKName,
        [switch]$ResolveObjectType,
        [string]$Domain
    )

    $flags = @()
    if ($Acl.Defaulted) {
        $flags += @("Defaulted")
    }

    if ($Acl.Protected) {
        $flags += @("Protected")
    }

    if ($Acl.AutoInherited) {
        $flags += @("Auto Inherited")
    }

    if ($Acl.AutoInheritReq) {
        $flags += @("Auto Inherit Requested")
    }

    if ($flags.Count -gt 0) {
        $Name = "$Name ($([string]::Join(", ", $flags)))"
    }

    if ($Acl.NullAcl) {
        if ($Summary) {
            Write-Output "$Name - <NULL>"
        }
        else {
            Write-Output $Name
            Write-Output " - <NULL ACL>"
            Write-Output ""
        }
    }
    elseif ($Acl.Count -eq 0) {
        if ($Summary) {
            Write-Output "$Name - <EMPTY>"
        }
        else {
            Write-Output $Name
            Write-Output " - <EMPTY ACL>"
            Write-Output ""
        }
    }
    else {
        Write-Output $Name
        if ($AuditOnly) {
            $Acl | Where-Object IsAuditAce | Format-NtAce -Type $Type -MapGeneric:$MapGeneric -Summary:$Summary -Container:$Container -SDKName:$SDKName -ResolveObjectType:$ResolveObjectType -Domain:$Domain
        }
        else {
            $Acl | Format-NtAce -Type $Type -MapGeneric:$MapGeneric -Summary:$Summary -Container:$Container -SDKName:$SDKName -ResolveObjectType:$ResolveObjectType -Domain:$Domain
        }
    }
}

<#
.SYNOPSIS
Formats an object's security descriptor as text.
.DESCRIPTION
This cmdlet formats the security descriptor to text for display in the console or piped to a file. Note that
by default the SACL won't be disabled even if you pass in a SD object with the SACL present. In those cases
change the SecurityInformation parameter to add Sacl or use ShowAll.
.PARAMETER Object
Specify an object to use for the security descriptor.
.PARAMETER SecurityDescriptor
Specify a security descriptor.
.PARAMETER Type
Specify the NT object type for the security descriptor.
.PARAMETER Path
Specify the path to an NT object for the security descriptor.
.PARAMETER SecurityInformation
Specify what parts of the security descriptor to format.
.PARAMETER MapGeneric
Specify to map access masks back to generic access rights for the object type.
.PARAMETER AsSddl
Specify to format the security descriptor as SDDL.
.PARAMETER Container
Specify to display the access mask from Container Access Rights.
.PARAMETER Acl
Specify a ACL to format.
.PARAMETER AuditOnly
Specify the ACL is a SACL otherwise a DACL.
.PARAMETER Summary
Specify to only print a shortened format removing redundant information.
.PARAMETER ShowAll
Specify to format all security descriptor information including the SACL.
.PARAMETER HideHeader
Specify to not print the security descriptor header.
.PARAMETER DisplayPath
Specify to display a path when using SecurityDescriptor or Acl formatting.
.PARAMETER SDKName
Specify to format the security descriptor using SDK names where available.
.PARAMETER ResolveObjectType
Specify to try and resolve the object type GUID from the local Active Directory.
.PARAMETER Domain
Specify to indicate the domain to query the object type from when resolving. Defaults to the current domain.
.OUTPUTS
None
.EXAMPLE
Format-NtSecurityDescriptor -Object $obj
Format the security descriptor of an object.
.EXAMPLE
Format-NtSecurityDescriptor -SecurityDescriptor $obj.SecurityDescriptor -Type $obj.NtType
Format the security descriptor for an object via it's properties.
.EXAMPLE
Format-NtSecurityDescriptor -SecurityDescriptor $sd
Format the security descriptor using a default type.
.EXAMPLE
Format-NtSecurityDescriptor -SecurityDescriptor $sd -Type File
Format the security descriptor assuming it's a File type.
.EXAMPLE
Format-NtSecurityDescriptor -Path \BaseNamedObjects
Format the security descriptor for an object from a path.
.EXAMPLE
Format-NtSecurityDescriptor -Object $obj -AsSddl
Format the security descriptor of an object as SDDL.
.EXAMPLE
Format-NtSecurityDescriptor -Object $obj -AsSddl -SecurityInformation Dacl, Label
Format the security descriptor of an object as SDDL with only DACL and Label.
#>
function Format-NtSecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName = "FromObject")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromObject", Mandatory, ValueFromPipeline)]
        [NtCoreLib.Security.Authorization.INtObjectSecurity]$Object,
        [Parameter(Position = 0, ParameterSetName = "FromSecurityDescriptor", Mandatory, ValueFromPipeline)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 0, ParameterSetName = "FromAccessCheck", Mandatory, ValueFromPipeline)]
        [NtObjectManager.Cmdlets.Accessible.CommonAccessCheckResult]$AccessCheckResult,
        [Parameter(Position = 0, ParameterSetName = "FromAcl", Mandatory)]
        [AllowEmptyCollection()]
        [NtCoreLib.Security.Authorization.Acl]$Acl,
        [Parameter(ParameterSetName = "FromAcl")]
        [switch]$AuditOnly,
        [Parameter(Position = 1, ParameterSetName = "FromSecurityDescriptor")]
        [Parameter(Position = 1, ParameterSetName = "FromAcl")]
        [NtCoreLib.NtType]$Type,
        [switch]$Container,
        [Parameter(Position = 0, ParameterSetName = "FromPath", Mandatory, ValueFromPipeline)]
        [string]$Path,
        [parameter(ParameterSetName = "FromPath")]
        [NtCoreLib.NtObject]$Root,
        [NtCoreLib.Security.Authorization.SecurityInformation]$SecurityInformation = "AllBasic",
        [switch]$MapGeneric,
        [alias("ToSddl")]
        [switch]$AsSddl,
        [switch]$Summary,
        [switch]$ShowAll,
        [switch]$HideHeader,
        [Parameter(ParameterSetName = "FromSecurityDescriptor")]
        [Parameter(ParameterSetName = "FromAcl")]
        [string]$DisplayPath = "",
        [switch]$SDKName,
        [switch]$ResolveObjectType,
        [string]$Domain
    )

    PROCESS {
        try {
            $sd, $t, $n = switch ($PsCmdlet.ParameterSetName) {
                "FromObject" {
                    $access = Get-NtAccessMask -SecurityInformation $SecurityInformation -ToGenericAccess
                    if (!$Object.IsAccessMaskGranted($access)) {
                        Write-Error "Object doesn't have $access access."
                        return
                    }
                    ($Object.GetSecurityDescriptor($SecurityInformation), $Object.NtType, $Object.ObjectName)
                }
                "FromPath" {
                    $access = Get-NtAccessMask -SecurityInformation $SecurityInformation -ToGenericAccess
                    Use-NtObject($obj = Get-NtObject -Path $Path -Root $Root -Access $access) {
                        ($obj.GetSecurityDescriptor($SecurityInformation), $obj.NtType, $obj.FullPath)
                    }
                }
                "FromSecurityDescriptor" {
                    $sd_type = $SecurityDescriptor.NtType
                    if ($sd_type -eq $null) {
                        $sd_type = $Type
                    }
                    ($SecurityDescriptor, $sd_type, $DisplayPath)
                }
                "FromAcl" {
                    $fake_sd = New-NtSecurityDescriptor
                    if ($AuditOnly) {
                        $fake_sd.Sacl = $Acl
                        $SecurityInformation = "Sacl"
                    }
                    else {
                        $fake_sd.Dacl = $Acl
                        $SecurityInformation = "Dacl"
                    }
                    ($fake_sd, $Type, $DisplayPath)
                }
                "FromAccessCheck" {
                    if ($AccessCheckResult.SecurityDescriptorBase64 -eq "") {
                        return
                    }
                    $check_sd = New-NtSecurityDescriptor -Base64 $AccessCheckResult.SecurityDescriptorBase64
                    $Type = Get-NtType $AccessCheckResult.TypeName
                    $Name = $AccessCheckResult.Name
                    ($check_sd, $Type, $Name)
                }
            }

            $si = $SecurityInformation
            if ($ShowAll) {
                $si = [NtCoreLib.Security.Authorization.SecurityInformation]::All
            }

            if ($AsSddl) {
                $sd.ToSddl($si) | Write-Output
                return
            }

            if ($null -eq $t) {
                Write-Warning "No type specified, formatting might be incorrect."
                $t = New-NtType Generic
            }

            if (-not $Container) {
                $Container = $sd.Container
            }

            if (!$Summary -and !$HideHeader) {
                if ($n -ne "") {
                    Write-Output "Path: $n"
                }
                Write-Output "Type: $($t.Name)"
                $sd_control = $sd.Control
                if ($SDKName) {
                    $sd_control = [NtCoreLib.Security.NtSecurity]::ControlFlagsToSDKName($sd_control)
                }
                Write-Output "Control: $sd_control"
                if ($null -ne $sd.RmControl) {
                    Write-Output $("RmControl: 0x{0:X02}" -f $sd.RmControl)
                }
                Write-Output ""
            }

            if ($null -eq $sd.Owner -and $null -eq $sd.Group `
                    -and $null -eq $sd.Dacl -and $null -eq $sd.Sacl) {
                Write-Output "<NO SECURITY INFORMATION>"
                return
            }

            if ($null -ne $sd.Owner -and (($si -band "Owner") -ne 0)) {
                $title = if ($sd.Owner.Defaulted) {
                    "<Owner> (Defaulted)"
                }
                else {
                    "<Owner>"
                }
                if ($Summary) {
                    Write-Output "$title : $($sd.Owner.Sid.Name)"
                }
                else {
                    Write-Output $title
                    Write-Output " - Name  : $($sd.Owner.Sid.Name)"
                    Write-Output " - Sid   : $($sd.Owner.Sid)"
                    Write-Output ""
                }
            }
            if ($null -ne $sd.Group -and (($si -band "Group") -ne 0)) {
                $title = if ($sd.Group.Defaulted) {
                    "<Group> (Defaulted)"
                }
                else {
                    "<Group>"
                }
                if ($Summary) {
                    Write-Output "$title : $($sd.Group.Sid.Name)"
                }
                else {
                    Write-Output $title
                    Write-Output " - Name  : $($sd.Group.Sid.Name)"
                    Write-Output " - Sid   : $($sd.Group.Sid)"
                    Write-Output ""
                }
            }
            if ($sd.DaclPresent -and (($si -band "Dacl") -ne 0)) {
                Format-NtAcl -Acl $sd.Dacl -Type $t -Name "<DACL>" -MapGeneric:$MapGeneric -Summary:$Summary -Container:$Container -SDKName:$SDKName -ResolveObjectType:$ResolveObjectType -Domain $Domain
            }
            if (($sd.HasAuditAce -or $sd.SaclNull) -and (($si -band "Sacl") -ne 0)) {
                Format-NtAcl -Acl $sd.Sacl -Type $t -Name "<SACL>" -MapGeneric:$MapGeneric -AuditOnly -Summary:$Summary -Container:$Container -SDKName:$SDKName -ResolveObjectType:$ResolveObjectType -Domain $Domain
            }
            $label = $sd.GetMandatoryLabel()
            if ($null -ne $label -and (($si -band "Label") -ne 0)) {
                Write-Output "<Mandatory Label>"
                Format-NtAce -Ace $label -Type $t -Summary:$Summary -Container:$Container -SDKName:$SDKName
            }
            $trust = $sd.ProcessTrustLabel
            if ($null -ne $trust -and (($si -band "ProcessTrustLabel") -ne 0)) {
                Write-Output "<Process Trust Label>"
                Format-NtAce -Ace $trust -Type $t -Summary:$Summary -Container:$Container -SDKName:$SDKName
            }
            if (($si -band "Attribute") -ne 0) {
                $attrs = $sd.ResourceAttributes
                if ($attrs.Count -gt 0) {
                    Write-Output "<Resource Attributes>"
                    foreach ($attr in $attrs) {
                        Format-NtAce -Ace $attr -Type $t -Summary:$Summary -Container:$Container -SDKName:$SDKName
                    }
                }
            }
            if (($si -band "AccessFilter") -ne 0) {
                $filters = $sd.AccessFilters
                if ($filters.Count -gt 0) {
                    Write-Output "<Access Filters>"
                    foreach ($filter in $filters) {
                        Format-NtAce -Ace $filter -Type $t -Summary:$Summary -Container:$Container -SDKName:$SDKName
                    }
                }
            }
            if (($si -band "Scope") -ne 0) {
                $scope = $sd.ScopedPolicyID
                if ($null -ne $scope) {
                    Write-Output "<Scoped Policy ID>"
                    Format-NtAce -Ace $scope -Type $t -Summary:$Summary -Container:$Container -SDKName:$SDKName
                }
            }
        }
        catch {
            Write-Error $_
        }
    }
}

<#
.SYNOPSIS
Get the security descriptor from an object.
.DESCRIPTION
This cmdlet gets the security descriptor from an object with specified list of security information.
.PARAMETER Object
The object to get the security descriptor from.
.PARAMETER SecurityInformation
The security information to get from the object.
.PARAMETER AsSddl
Convert the security descriptor to an SDDL string.
.PARAMETER Process
Specify process to a read a security descriptor from memory.
.PARAMETER Address
Specify the address in the process to read the security descriptor.
.PARAMETER Path
Specify an object path to get the security descriptor from.
.PARAMETER TypeName
Specify the type name of the object at Path. Needed if the module cannot automatically determine the NT type to open.
.PARAMETER Root
Specify a root object for Path.
.PARAMETER NamedPipeDefault
 Specify to get the default security descriptor for a named pipe.
.INPUTS
NtCoreLib.NtObject[]
.OUTPUTS
NtCoreLib.Security.Authorization.SecurityDescriptor
string
.EXAMPLE
Get-NtSecurityDescriptor $obj
Get the security descriptor with default security information.
.EXAMPLE
Get-NtSecurityDescriptor $obj Dacl,Owner,Group
Get the security descriptor with DACL, OWNER and GROUP values.
.EXAMPLE
Get-NtSecurityDescriptor $obj Dacl -AsSddl
Get the security descriptor with DACL and output as an SDDL string.
.EXAMPLE
Get-NtSecurityDescriptor \BaseNamedObjects\ABC
Get the security descriptor from path \BaseNamedObjects\ABC.
.EXAMPLE
Get-NtSecurityDescriptor \??\C:\Windows -TypeName File
Get the security descriptor from c:\windows. Needs explicit NtType name of File to work.
.EXAMPLE
@($obj1, $obj2) | Get-NtSecurityDescriptor
Get the security descriptors from an array of objects.
.EXAMPLE
Get-NtSecurityDescriptor -Process $process -Address 0x12345678
Get the security descriptor from another process at address 0x12345678.
.EXAMPLE
Get-NtSecurityDescriptor -NamedPipeDefault
Get the default security descriptor for a named pipe.
.EXAMPLE
Get-NtSecurityDescriptor -ProcessId 1234
Get the security descriptor for Process ID 1234.
.EXAMPLE
Get-NtSecurityDescriptor -ThreadId 5678
Get the security descriptor for Thread ID 5678.
#>
function Get-NtSecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName = "FromObject")]
    param (
        [parameter(Mandatory, Position = 0, ValueFromPipeline, ParameterSetName = "FromObject")]
        [NtCoreLib.Security.Authorization.INtObjectSecurity]$Object,
        [parameter(Position = 1, ParameterSetName = "FromObject")]
        [parameter(Position = 1, ParameterSetName = "FromPath")]
        [parameter(ParameterSetName = "FromPid")]
        [parameter(ParameterSetName = "FromTid")]
        [NtCoreLib.Security.Authorization.SecurityInformation]$SecurityInformation = "AllBasic",
        [parameter(Mandatory, ParameterSetName = "FromProcess")]
        [NtCoreLib.NtProcess]$Process,
        [parameter(Mandatory, ParameterSetName = "FromProcess")]
        [int64]$Address,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromPath")]
        [string]$Path,
        [parameter(ParameterSetName = "FromPath")]
        [string]$TypeName,
        [parameter(ParameterSetName = "FromPath")]
        [NtCoreLib.NtObject]$Root,
        [parameter(Mandatory, ParameterSetName = "FromPid")]
        [alias("pid")]
        [int]$ProcessId,
        [parameter(Mandatory, ParameterSetName = "FromTid")]
        [alias("tid")]
        [int]$ThreadId,
        [parameter(Mandatory, ParameterSetName = "FromNp")]
        [switch]$NamedPipeDefault,
        [alias("ToSddl")]
        [switch]$AsSddl
    )
    PROCESS {
        $sd = switch ($PsCmdlet.ParameterSetName) {
            "FromObject" {
                $Object.GetSecurityDescriptor($SecurityInformation)
            }
            "FromProcess" {
                [NtCoreLib.Security.Authorization.SecurityDescriptor]::new($Process, [IntPtr]::new($Address))
            }
            "FromPath" {
                $mask = Get-NtAccessMask -SecurityInformation $SecurityInformation -ToGenericAccess
                Use-NtObject($obj = Get-NtObject -Path $Path -Root $Root -TypeName $TypeName -Access $mask) {
                    $obj.GetSecurityDescriptor($SecurityInformation)
                }
            }
            "FromPid" {
                $mask = Get-NtAccessMask -SecurityInformation $SecurityInformation -ToSpecificAccess Process
                Use-NtObject($obj = Get-NtProcess -ProcessId $ProcessId -Access $mask) {
                    $obj.GetSecurityDescriptor($SecurityInformation)
                }
            }
            "FromTid" {
                $mask = Get-NtAccessMask -SecurityInformation $SecurityInformation -ToSpecificAccess Thread
                Use-NtObject($obj = Get-NtThread -ThreadId $ThreadId -Access $mask) {
                    $obj.GetSecurityDescriptor($SecurityInformation)
                }
            }
            "FromNp" {
                $dacl = [NtCoreLib.NtNamedPipeFile]::GetDefaultNamedPipeAcl();
                New-NtSecurityDescriptor -Dacl $dacl -Type File
            }
        }
        if ($AsSddl) {
            $sd.ToSddl($SecurityInformation)
        }
        else {
            $sd
        }
    }
}

<#
.SYNOPSIS
Set the security descriptor for an object.
.DESCRIPTION
This cmdlet sets the security descriptor for an object with specified list of security information.
.PARAMETER Object
The object to set the security descriptor to.
.PARAMETER SecurityInformation
The security information to set obj the object.
.PARAMETER Path
Specify an object path to set the security descriptor to.
.PARAMETER Root
Specify a root object for Path.
.PARAMETER TypeName
Specify the type name of the object at Path. Needed if the module cannot automatically determine the NT type to open.
.PARAMETER SecurityDescriptor
The security descriptor to set. Can specify an SDDL string which will be auto-converted.
.INPUTS
NtCoreLib.NtObject[]
.OUTPUTS
None
.EXAMPLE
Set-NtSecurityDescriptor $obj $sd Dacl
Set the DACL of an object using a SecurityDescriptor object.
.EXAMPLE
Set-NtSecurityDescriptor $obj "D:(A;;GA;;;WD)" Dacl
Set the DACL of an object based on an SDDL string.
#>
function Set-NtSecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName = "ToObject")]
    param (
        [parameter(Mandatory, Position = 0, ValueFromPipeline, ParameterSetName = "ToObject")]
        [NtCoreLib.Security.Authorization.INtObjectSecurity]$Object,
        [parameter(Mandatory, Position = 0, ParameterSetName = "ToPath")]
        [string]$Path,
        [parameter(ParameterSetName = "ToPath")]
        [NtCoreLib.NtObject]$Root,
        [parameter(Mandatory, Position = 1)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [parameter(Mandatory, Position = 2)]
        [NtCoreLib.Security.Authorization.SecurityInformation]$SecurityInformation,
        [parameter(ParameterSetName = "ToPath")]
        [string]$TypeName

    )
    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "ToObject" {
                $Object.SetSecurityDescriptor($SecurityDescriptor, $SecurityInformation)
            }
            "ToPath" {
                $access = Get-NtAccessMask -SecurityInformation $SecurityInformation -ToGenericAccess -SetSecurity
                Use-NtObject($obj = Get-NtObject -Path $Path -Root $Root -TypeName $TypeName -Access $access) {
                    $obj.SetSecurityDescriptor($SecurityDescriptor, $SecurityInformation)
                }
            }
        }
    }
}

<#
.SYNOPSIS
Copies a security descriptor to a new one.
.DESCRIPTION
This cmdlet copies the details from a security descriptor into a new object so
that it can be modified without affecting the other.
.PARAMETER SecurityDescriptor
The security descriptor to copy.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.SecurityDescriptor
#>
function Copy-NtSecurityDescriptor {
    Param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
    )
    $SecurityDescriptor.Clone() | Write-Output
}

<#
.SYNOPSIS
Edits an existing security descriptor.
.DESCRIPTION
This cmdlet edits an existing security descriptor in-place. This can be based on
a new security descriptor and additional information. If PassThru is specified
the the SD is not editing in place, a clone of the SD will be returned.
.PARAMETER SecurityDescriptor
The security descriptor to edit.
.PARAMETER NewSecurityDescriptor
The security to update with.
.PARAMETER SecurityInformation
Specify the parts of the security descriptor to edit.
.PARAMETER Token
Specify optional token used to edit the security descriptor.
.PARAMETER Flags
Specify optional auto inherit flags.
.PARAMETER Type
Specify the NT type to use for the update. Defaults to using the
type from $SecurityDescriptor.
.PARAMETER MapGeneric
Map generic access rights to specific access rights.
.PARAMETER PassThru
Passthrough the security descriptor.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.SecurityDescriptor
.EXAMPLE
Edit-NtSecurityDescriptor $sd -CanonicalizeDacl
Canonicalize the security descriptor's DACL.
.EXAMPLE
Edit-NtSecurityDescriptor $sd -MapGenericAccess
Map the security descriptor's generic access to type specific access.
.EXAMPLE
Copy-NtSecurityDescriptor $sd | Edit-NtSecurityDescriptor -MapGenericAccess -PassThru
Make a copy of a security descriptor and edit the copy.
#>
function Edit-NtSecurityDescriptor {
    Param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory, ParameterSetName = "ModifySd")]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$NewSecurityDescriptor,
        [Parameter(Position = 2, Mandatory, ParameterSetName = "ModifySd")]
        [NtCoreLib.Security.Authorization.SecurityInformation]$SecurityInformation,
        [Parameter(ParameterSetName = "ModifySd")]
        [NtCoreLib.NtToken]$Token,
        [Parameter(ParameterSetName = "ModifySd")]
        [NtCoreLib.Security.Authorization.SecurityAutoInheritFlags]$Flags = 0,
        [Parameter(ParameterSetName = "ModifySd")]
        [Parameter(ParameterSetName = "ToAutoInherit")]
        [Parameter(ParameterSetName = "MapGenericSd")]
        [Parameter(ParameterSetName = "UnmapGenericSd")]
        [NtCoreLib.NtType]$Type,
        [Parameter(ParameterSetName = "CanonicalizeSd")]
        [switch]$CanonicalizeDacl,
        [Parameter(ParameterSetName = "CanonicalizeSd")]
        [switch]$CanonicalizeSacl,
        [Parameter(Mandatory, ParameterSetName = "MapGenericSd")]
        [switch]$MapGeneric,
        [Parameter(Mandatory, ParameterSetName = "UnmapGenericSd")]
        [switch]$UnmapGeneric,
        [Parameter(Mandatory, ParameterSetName = "ToAutoInherit")]
        [switch]$ConvertToAutoInherit,
        [Parameter(ParameterSetName = "ToAutoInherit")]
        [switch]$Container,
        [Parameter(ParameterSetName = "ToAutoInherit")]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$Parent,
        [Parameter(ParameterSetName = "ToAutoInherit")]
        [Nullable[Guid]]$ObjectType = $null,
        [Parameter(ParameterSetName = "StandardizeSd")]
        [switch]$Standardize,
        [switch]$PassThru
    )

    if ($PassThru) {
        $SecurityDescriptor = Copy-NtSecurityDescriptor $SecurityDescriptor
    }

    if ($PSCmdlet.ParameterSetName -ne "CanonicalizeSd") {
        if ($null -eq $Type) {
            $Type = $SecurityDescriptor.NtType
            if ($null -eq $Type) {
                Write-Warning "Original type not available, defaulting to File."
                $Type = Get-NtType "File"
            }
        }
    }

    if ($PsCmdlet.ParameterSetName -eq "ModifySd") {
        $SecurityDescriptor.Modify($NewSecurityDescriptor, $SecurityInformation, `
                $Flags, $Token, $Type.GenericMapping)
    }
    elseif ($PsCmdlet.ParameterSetName -eq "CanonicalizeSd") {
        if ($CanonicalizeDacl) {
            $SecurityDescriptor.CanonicalizeDacl()
        }
        if ($CanonicalizeSacl) {
            $SecurityDescriptor.CanonicalizeSacl()
        }
    }
    elseif ($PsCmdlet.ParameterSetName -eq "MapGenericSd") {
        $SecurityDescriptor.MapGenericAccess($Type)
    }
    elseif ($PsCmdlet.ParameterSetName -eq "UnmapGenericSd") {
        $SecurityDescriptor.UnmapGenericAccess($Type)
    }
    elseif ($PsCmdlet.ParameterSetName -eq "ToAutoInherit") {
        $SecurityDescriptor.ConvertToAutoInherit($Parent,
            $ObjectType, $Container, $Type.GenericMapping)
    }
    elseif ($PSCmdlet.ParameterSetName -eq "StandardizeSd") {
        $SecurityDescriptor.Standardize()
    }

    if ($PassThru) {
        $SecurityDescriptor | Write-Output
    }
}

<#
.SYNOPSIS
Sets the owner for a security descriptor.
.DESCRIPTION
This cmdlet sets the owner of a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.PARAMETER Owner
The owner SID to set.
.PARAMETER Name
The name of the group to set.
.PARAMETER KnownSid
The well known SID to set.
.PARAMETER Defaulted
Specify whether the owner is defaulted.
.PARAMETER
.INPUTS
None
.OUTPUTS
None
#>
function Set-NtSecurityDescriptorOwner {
    [CmdletBinding(DefaultParameterSetName = "FromSid")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory, ParameterSetName = "FromSid")]
        [NtCoreLib.Security.Authorization.Sid]$Owner,
        [Parameter(Mandatory, ParameterSetName = "FromName")]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName = "FromKnownSid")]
        [NtCoreLib.Security.Authorization.KnownSidValue]$KnownSid,
        [switch]$Defaulted
    )

    $sid = switch ($PsCmdlet.ParameterSetName) {
        "FromSid" {
            $Owner
        }
        "FromName" {
            Get-NtSid -Name $Name
        }
        "FromKnownSid" {
            Get-NtSid -KnownSid $KnownSid
        }
    }

    $SecurityDescriptor.Owner = [NtCoreLib.Security.Authorization.SecurityDescriptorSid]::new($sid, $Defaulted)
}

<#
.SYNOPSIS
Test various properties of the security descriptor..
.DESCRIPTION
This cmdlet tests various properties of the security descriptor. The default is
to check if the DACL is present.
.PARAMETER SecurityDescriptor
The security descriptor to test.
.PARAMETER DaclPresent
Test if the DACL is present.
.PARAMETER SaclPresent
Test if the SACL is present.
.PARAMETER DaclCanonical
Test if the DACL is canonical.
.PARAMETER SaclCanonical
Test if the SACL is canonical.
.PARAMETER DaclDefaulted
Test if the DACL is defaulted.
.PARAMETER DaclAutoInherited
Test if the DACL is auto-inherited.
.PARAMETER SaclDefaulted
Test if the DACL is defaulted.
.PARAMETER SaclAutoInherited
Test if the DACL is auto-inherited.
.INPUTS
None
.OUTPUTS
Boolean or PSObject.
#>
function Test-NtSecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName = "DaclPresent")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(ParameterSetName = "DaclPresent")]
        [switch]$DaclPresent,
        [Parameter(Mandatory, ParameterSetName = "SaclPresent")]
        [switch]$SaclPresent,
        [Parameter(Mandatory, ParameterSetName = "DaclCanonical")]
        [switch]$DaclCanonical,
        [Parameter(Mandatory, ParameterSetName = "SaclCanonical")]
        [switch]$SaclCanonical,
        [Parameter(Mandatory, ParameterSetName = "DaclDefaulted")]
        [switch]$DaclDefaulted,
        [Parameter(Mandatory, ParameterSetName = "DaclAutoInherited")]
        [switch]$DaclAutoInherited,
        [Parameter(Mandatory, ParameterSetName = "SaclDefaulted")]
        [switch]$SaclDefaulted,
        [Parameter(Mandatory, ParameterSetName = "SaclAutoInherited")]
        [switch]$SaclAutoInherited,
        [Parameter(ParameterSetName = "DaclNull")]
        [switch]$DaclNull,
        [Parameter(Mandatory, ParameterSetName = "SaclNull")]
        [switch]$SaclNull
    )

    $obj = switch ($PSCmdlet.ParameterSetName) {
        "DaclPresent" { $SecurityDescriptor.DaclPresent }
        "SaclPresent" { $SecurityDescriptor.SaclPresent }
        "DaclCanonical" { $SecurityDescriptor.DaclCanonical }
        "SaclCanonical" { $SecurityDescriptor.SaclCanonical }
        "DaclDefaulted" { $SecurityDescriptor.DaclDefaulted }
        "SaclDefaulted" { $SecurityDescriptor.SaclDefaulted }
        "DaclAutoInherited" { $SecurityDescriptor.DaclAutoInherited }
        "SaclAutoInherited" { $SecurityDescriptor.SaclAutoInherited }
        "DaclNull" { $SecurityDescriptor.DaclNull }
        "SaclNull" { $SecurityDescriptor.SaclNull }
    }
    Write-Output $obj
}

<#
.SYNOPSIS
Get the owner from a security descriptor.
.DESCRIPTION
This cmdlet gets the Owner field from a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to query.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.SecurityDescriptorSid
#>
function Get-NtSecurityDescriptorOwner {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
    )
    $SecurityDescriptor.Owner | Write-Output
}

<#
.SYNOPSIS
Get the group from a security descriptor.
.DESCRIPTION
This cmdlet gets the Group field from a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to query.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.SecurityDescriptorSid
#>
function Get-NtSecurityDescriptorGroup {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
    )
    $SecurityDescriptor.Group | Write-Output
}

<#
.SYNOPSIS
Get the DACL from a security descriptor.
.DESCRIPTION
This cmdlet gets the Dacl field from a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to query.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.Acl
#>
function Get-NtSecurityDescriptorDacl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
    )
    Write-Output $SecurityDescriptor.Dacl -NoEnumerate
}

<#
.SYNOPSIS
Get the SACL from a security descriptor.
.DESCRIPTION
This cmdlet gets the Sacl field from a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to query.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.Acl
#>
function Get-NtSecurityDescriptorSacl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
    )
    Write-Output $SecurityDescriptor.Sacl -NoEnumerate
}

<#
.SYNOPSIS
Get the Control from a security descriptor.
.DESCRIPTION
This cmdlet gets the Control field from a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to query.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.SecurityDescriptorControl
#>
function Get-NtSecurityDescriptorControl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
    )
    Write-Output $SecurityDescriptor.Control
}

<#
.SYNOPSIS
Get the Integrity Level from a security descriptor.
.DESCRIPTION
This cmdlet gets the Integrity Level field from a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to query.
.PARAMETER Sid
Get the Integrity Level as a SID.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.Sid or NtCoreLib.TokenIntegrityLevel
#>
function Get-NtSecurityDescriptorIntegrityLevel {
    [CmdletBinding(DefaultParameterSetName = "ToIL")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(ParameterSetName = "ToSid")]
        [switch]$AsSid,
        [Parameter(ParameterSetName = "ToAce")]
        [switch]$AsAce
    )

    if (!$SecurityDescriptor.HasMandatoryLabelAce) {
        return
    }

    switch ($PSCmdlet.ParameterSetName) {
        "ToIL" {
            $SecurityDescriptor.IntegrityLevel
        }
        "ToSid" {
            $SecurityDescriptor.MandatoryLabel.Sid
        }
        "ToAce" {
            $SecurityDescriptor.MandatoryLabel
        }
    }
}

<#
.SYNOPSIS
Sets Control flags for a security descriptor.
.DESCRIPTION
This cmdlet sets Control flags for a security descriptor. Note that you can't
remove the DaclPresent or SaclPresent. For that use Remove-NtSecurityDescriptorDacl
or Remove-NtSecurityDescriptorSacl.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.PARAMETER Control
The control flags to set.
.PARAMETER PassThru
Pass through the final control flags.
.INPUTS
None
.OUTPUTS
None
#>
function Set-NtSecurityDescriptorControl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptorControl]$Control,
        [switch]$PassThru
    )
    $SecurityDescriptor.Control = $Control
    if ($PassThru) {
        $SecurityDescriptor.Control | Write-Output
    }
}

<#
.SYNOPSIS
Adds Control flags for a security descriptor.
.DESCRIPTION
This cmdlet adds Control flags for a security descriptor. Note that you can't
remove the DaclPresent or SaclPresent. For that use Remove-NtSecurityDescriptorDacl
or Remove-NtSecurityDescriptorSacl.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.PARAMETER Control
The control flags to add.
.PARAMETER PassThru
Pass through the final control flags.
.INPUTS
None
.OUTPUTS
None
#>
function Add-NtSecurityDescriptorControl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptorControl]$Control,
        [switch]$PassThru
    )

    $curr_flags = $SecurityDescriptor.Control
    $new_flags = [int]$curr_flags -bor $Control
    $SecurityDescriptor.Control = $new_flags
    if ($PassThru) {
        $SecurityDescriptor.Control | Write-Output
    }
}

<#
.SYNOPSIS
Removes Control flags for a security descriptor.
.DESCRIPTION
This cmdlet removes Control flags for a security descriptor. Note that you can't
remove the DaclPresent or SaclPresent. For that use Remove-NtSecurityDescriptorDacl
or Remove-NtSecurityDescriptorSacl.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.PARAMETER Control
The control flags to remove.
.PARAMETER PassThru
Pass through the final control flags.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-NtSecurityDescriptorControl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptorControl]$Control,
        [switch]$PassThru
    )

    $curr_flags = $SecurityDescriptor.Control
    $new_flags = [int]$curr_flags -band -bnot $Control
    $SecurityDescriptor.Control = $new_flags
    if ($PassThru) {
        $SecurityDescriptor.Control | Write-Output
    }
}

<#
.SYNOPSIS
Creates a new ACL object.
.DESCRIPTION
This cmdlet creates a new ACL object.
.PARAMETER Ace
List of ACEs to create the ACL from.
.PARAMETER Defaulted
Specify whether the ACL is defaulted.
.PARAMETER NullAcl
Specify whether the ACL is NULL.
.PARAMETER AutoInheritReq
Specify to set the Auto Inherit Requested flag.
.PARAMETER AutoInherited
Specify to set the Auto Inherited flag.
.PARAMETER Protected
Specify to set the Protected flag.
.PARAMETER Defaulted
Specify to set the Defaulted flag.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.Acl
#>
function New-NtAcl {
    [CmdletBinding(DefaultParameterSetName = "FromAce")]
    Param(
        [Parameter(Mandatory, ParameterSetName = "NullAcl")]
        [switch]$NullAcl,
        [Parameter(ParameterSetName = "FromAce")]
        [NtCoreLib.Security.Authorization.Ace[]]$Ace,
        [switch]$AutoInheritReq,
        [switch]$AutoInherited,
        [switch]$Protected,
        [switch]$Defaulted
    )

    $acl = New-Object NtCoreLib.Security.Authorization.Acl
    $acl.AutoInherited = $AutoInherited
    $acl.AutoInheritReq = $AutoInheritReq
    $acl.Protected = $Protected
    $acl.Defaulted = $Defaulted
    switch ($PsCmdlet.ParameterSetName) {
        "FromAce" {
            if ($null -ne $Ace) {
                $acl.AddRange($Ace)
            }
        }
        "NullAcl" {
            $acl.NullAcl = $true
        }
    }

    Write-Output $acl -NoEnumerate
}

<#
.SYNOPSIS
Sets the DACL for a security descriptor.
.DESCRIPTION
This cmdlet sets the DACL of a security descriptor. It'll replace any existing DACL assigned.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.PARAMETER Ace
List of ACEs to create the ACL from.
.PARAMETER Defaulted
Specify whether the ACL is defaulted.
.PARAMETER NullAcl
Specify whether the ACL is NULL.
.PARAMETER AutoInheritReq
Specify to set the Auto Inherit Requested flag.
.PARAMETER AutoInherited
Specify to set the Auto Inherited flag.
.PARAMETER Protected
Specify to set the Protected flag.
.PARAMETER Defaulted
Specify to set the Defaulted flag.
.PARAMETER PassThru
Specify to return the new ACL.
.PARAMETER Remove
Specify to remove the ACL.
.INPUTS
None
.OUTPUTS
None
#>
function Set-NtSecurityDescriptorDacl {
    [CmdletBinding(DefaultParameterSetName = "FromAce")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Mandatory, ParameterSetName = "NullAcl")]
        [switch]$NullAcl,
        [Parameter(ParameterSetName = "FromAce")]
        [NtCoreLib.Security.Authorization.Ace[]]$Ace,
        [Parameter(ParameterSetName = "NullAcl")]
        [Parameter(ParameterSetName = "FromAce")]
        [switch]$AutoInheritReq,
        [Parameter(ParameterSetName = "NullAcl")]
        [Parameter(ParameterSetName = "FromAce")]
        [switch]$AutoInherited,
        [Parameter(ParameterSetName = "NullAcl")]
        [Parameter(ParameterSetName = "FromAce")]
        [switch]$Protected,
        [Parameter(ParameterSetName = "NullAcl")]
        [Parameter(ParameterSetName = "FromAce")]
        [switch]$Defaulted,
        [Parameter(ParameterSetName = "NullAcl")]
        [Parameter(ParameterSetName = "FromAce")]
        [switch]$PassThru
    )

    $args = @{
        AutoInheritReq = $AutoInheritReq
        AutoInherited  = $AutoInherited
        Protected      = $Protected
        Defaulted      = $Defaulted
    }

    $SecurityDescriptor.Dacl = if ($PSCmdlet.ParameterSetName -eq "NullAcl") {
        New-NtAcl @args -NullAcl
    }
    else {
        New-NtAcl @args -Ace $Ace
    }

    if ($PassThru) {
        Write-Output $SecurityDescriptor.Dacl -NoEnumerate
    }
}

<#
.SYNOPSIS
Sets the SACL for a security descriptor.
.DESCRIPTION
This cmdlet sets the SACL of a security descriptor. It'll replace any existing SACL assigned.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.PARAMETER Ace
List of ACEs to create the ACL from.
.PARAMETER Defaulted
Specify whether the ACL is defaulted.
.PARAMETER NullAcl
Specify whether the ACL is NULL.
.PARAMETER AutoInheritReq
Specify to set the Auto Inherit Requested flag.
.PARAMETER AutoInherited
Specify to set the Auto Inherited flag.
.PARAMETER Protected
Specify to set the Protected flag.
.PARAMETER Defaulted
Specify to set the Defaulted flag.
.PARAMETER PassThru
Specify to return the new ACL.
.PARAMETER Remove
Specify to remove the ACL.
.PARAMETER
.INPUTS
None
.OUTPUTS
None
#>
function Set-NtSecurityDescriptorSacl {
    [CmdletBinding(DefaultParameterSetName = "FromAce")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Mandatory, ParameterSetName = "NullAcl")]
        [switch]$NullAcl,
        [Parameter(ParameterSetName = "FromAce")]
        [NtCoreLib.Security.Authorization.Ace[]]$Ace,
        [Parameter(ParameterSetName = "NullAcl")]
        [Parameter(ParameterSetName = "FromAce")]
        [switch]$AutoInheritReq,
        [Parameter(ParameterSetName = "NullAcl")]
        [Parameter(ParameterSetName = "FromAce")]
        [switch]$AutoInherited,
        [Parameter(ParameterSetName = "NullAcl")]
        [Parameter(ParameterSetName = "FromAce")]
        [switch]$Protected,
        [Parameter(ParameterSetName = "NullAcl")]
        [Parameter(ParameterSetName = "FromAce")]
        [switch]$Defaulted,
        [Parameter(ParameterSetName = "NullAcl")]
        [Parameter(ParameterSetName = "FromAce")]
        [switch]$PassThru
    )

    $args = @{
        AutoInheritReq = $AutoInheritReq
        AutoInherited  = $AutoInherited
        Protected      = $Protected
        Defaulted      = $Defaulted
    }

    $SecurityDescriptor.Sacl = if ($PSCmdlet.ParameterSetName -eq "NullAcl") {
        New-NtAcl @args -NullAcl
    }
    else {
        New-NtAcl @args -Ace $Ace
    }
    if ($PassThru) {
        Write-Output $SecurityDescriptor.Sacl -NoEnumerate
    }
}

<#
.SYNOPSIS
Removes the DACL for a security descriptor.
.DESCRIPTION
This cmdlet removes the DACL of a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-NtSecurityDescriptorDacl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
    )
    $SecurityDescriptor.Dacl = $null
}

<#
.SYNOPSIS
Removes the SACL for a security descriptor.
.DESCRIPTION
This cmdlet removes the SACL of a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-NtSecurityDescriptorSacl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
    )
    $SecurityDescriptor.Sacl = $null
}

<#
.SYNOPSIS
Clears the DACL for a security descriptor.
.DESCRIPTION
This cmdlet clears the DACL of a security descriptor and unsets NullAcl. If no DACL
is present then nothing modification is performed.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.INPUTS
None
.OUTPUTS
None
#>
function Clear-NtSecurityDescriptorDacl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
    )

    if ($SecurityDescriptor.DaclPresent) {
        $SecurityDescriptor.Dacl.Clear()
        $SecurityDescriptor.Dacl.NullAcl = $false
    }
}

<#
.SYNOPSIS
Clears the SACL for a security descriptor.
.DESCRIPTION
This cmdlet clears the SACL of a security descriptor and unsets NullAcl. If no SACL
is present then nothing modification is performed.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.INPUTS
None
.OUTPUTS
None
#>
function Clear-NtSecurityDescriptorSacl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
    )
    if ($SecurityDescriptor.SaclPresent) {
        $SecurityDescriptor.Sacl.Clear()
        $SecurityDescriptor.Sacl.NullAcl = $false
    }
}

<#
.SYNOPSIS
Removes the owner for a security descriptor.
.DESCRIPTION
This cmdlet removes the owner of a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-NtSecurityDescriptorOwner {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
    )
    $SecurityDescriptor.Owner = $null
}

<#
.SYNOPSIS
Sets the group for a security descriptor.
.DESCRIPTION
This cmdlet sets the group of a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.PARAMETER Group
The group SID to set.
.PARAMETER Name
The name of the group to set.
.PARAMETER KnownSid
The well known SID to set.
.PARAMETER Defaulted
Specify whether the group is defaulted.
.INPUTS
None
.OUTPUTS
None
#>
function Set-NtSecurityDescriptorGroup {
    [CmdletBinding(DefaultParameterSetName = "FromSid")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory, ParameterSetName = "FromSid")]
        [NtCoreLib.Security.Authorization.Sid]$Group,
        [Parameter(Mandatory, ParameterSetName = "FromName")]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName = "FromKnownSid")]
        [NtCoreLib.Security.Authorization.KnownSidValue]$KnownSid,
        [switch]$Defaulted
    )

    $sid = switch ($PsCmdlet.ParameterSetName) {
        "FromSid" {
            $Group
        }
        "FromName" {
            Get-NtSid -Name $Name
        }
        "FromKnownSid" {
            Get-NtSid -KnownSid $KnownSid
        }
    }

    $SecurityDescriptor.Group = [NtCoreLib.Security.Authorization.SecurityDescriptorSid]::new($sid, $Defaulted)
}

<#
.SYNOPSIS
Removes the group for a security descriptor.
.DESCRIPTION
This cmdlet removes the group of a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-NtSecurityDescriptorGroup {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
    )
    $SecurityDescriptor.Group = $null
}

<#
.SYNOPSIS
Removes the integrity level for a security descriptor.
.DESCRIPTION
This cmdlet removes the integrity level of a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-NtSecurityDescriptorIntegrityLevel {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
    )
    $SecurityDescriptor.RemoveMandatoryLabel()
}

<#
.SYNOPSIS
Sets the integrity level for a security descriptor.
.DESCRIPTION
This cmdlet sets the integrity level for a security descriptor with a specified policy and flags.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.PARAMETER IntegrityLevel
Specify the integrity level.
.PARAMETER Sid
Specify the integrity level as a SID.
.PARAMETER Flags
Specify the ACE flags.
.PARAMETER Policy
Specify the ACE flags.
.INPUTS
None
.OUTPUTS
None
#>
function Set-NtSecurityDescriptorIntegrityLevel {
    [CmdletBinding(DefaultParameterSetName = "FromLevel")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory, ParameterSetName = "FromSid")]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [Parameter(Position = 1, Mandatory, ParameterSetName = "FromLevel")]
        [NtCoreLib.TokenIntegrityLevel]$IntegrityLevel,
        [Parameter(ParameterSetName = "FromLevel")]
        [Parameter(ParameterSetName = "FromSid")]
        [NtCoreLib.Security.Authorization.AceFlags]$Flags = 0,
        [Parameter(ParameterSetName = "FromLevel")]
        [Parameter(ParameterSetName = "FromSid")]
        [NtCoreLib.Security.Authorization.MandatoryLabelPolicy]$Policy = "NoWriteUp"
    )

    switch ($PSCmdlet.ParameterSetName) {
        "FromSid" {
            $SecurityDescriptor.AddMandatoryLabel($Sid, $Flags, $Policy)
        }
        "FromLevel" {
            $SecurityDescriptor.AddMandatoryLabel($IntegrityLevel, $Flags, $Policy)
        }
    }
}

<#
.SYNOPSIS
Converts an ACE condition string expression to a byte array or a parsed object.
.DESCRIPTION
This cmdlet gets a byte array or a parsed object for an ACE conditional string expression.
.PARAMETER Condition
The condition string expression.
.PARAMETER AsObject
Specify to the return the conditional expression as a parsed object.
.INPUTS
None
.OUTPUTS
byte[]
NtCoreLib.Security.Authorization.ConditionalExpression.ConditionalExpression
.EXAMPLE
ConvertFrom-NtAceCondition -Condition 'WIN://TokenId == "TEST"'
Gets the data for the condition expression 'WIN://TokenId == "TEST"'
.EXAMPLE
ConvertFrom-NtAceCondition -Condition 'WIN://TokenId == "TEST"' -AsObject
Gets the object for the condition expression 'WIN://TokenId == "TEST"'
#>
function ConvertFrom-NtAceCondition {
    [CmdletBinding(DefaultParameterSetName = "AsBytes")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Condition,
        [Parameter(Mandatory, ParameterSetName="AsObject")]
        [switch]$AsObject
    )

    if ($AsObject) {
        [NtCoreLib.Security.Authorization.ConditionalExpression.ConditionalExpression]::Parse($Condition)
    } else {
        [NtCoreLib.Security.NtSecurity]::StringToConditionalAce($Condition)
    }
}

<#
.SYNOPSIS
Converts an ACE condition byte array to a string.
.DESCRIPTION
This cmdlet converts a byte array for an ACE conditional expression into a string.
.PARAMETER ConditionData
The condition as a byte array.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
ConvertTo-NtAceCondition -Data $ba
Converts the byte array to a conditional expression string.
#>
function ConvertTo-NtAceCondition {
    [CmdletBinding(DefaultParameterSetName = "FromLevel")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [byte[]]$ConditionData
    )

    [NtCoreLib.Security.NtSecurity]::ConditionalAceToString($ConditionData)
}

<#
.SYNOPSIS
Converts a security descriptor to a self-relative byte array or base64 string.
.DESCRIPTION
This cmdlet converts a security descriptor to a self-relative byte array or a base64 string.
.PARAMETER SecurityDescriptor
The security descriptor to convert.
.PARAMETER AsBase64
Converts the self-relative SD to base64 string.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
ConvertFrom-NtSecurityDescriptor -SecurityDescriptor "O:SYG:SYD:(A;;GA;;;WD)"
Converts security descriptor to byte array.
.EXAMPLE
ConvertFrom-NtSecurityDescriptor -SecurityDescriptor "O:SYG:SYD:(A;;GA;;;WD)" -AsBase64
Converts security descriptor to a base64 string.
.EXAMPLE
ConvertFrom-NtSecurityDescriptor -SecurityDescriptor "O:SYG:SYD:(A;;GA;;;WD)" -AsBase64 -InsertLineBreaks
Converts security descriptor to a base64 string with line breaks.
#>
function ConvertFrom-NtSecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName = "ToBytes")]
    Param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Mandatory, ParameterSetName = "ToBase64")]
        [alias("Base64")]
        [switch]$AsBase64,
        [Parameter(ParameterSetName = "ToBase64")]
        [switch]$InsertLineBreaks
    )

    PROCESS {
        if ($AsBase64) {
            $SecurityDescriptor.ToBase64($InsertLineBreaks) | Write-Output
        }
        else {
            $SecurityDescriptor.ToByteArray() | Write-Output -NoEnumerate
        }
    }
}

<#
.SYNOPSIS
Converts a SID to a byte array.
.DESCRIPTION
This cmdlet converts a SID to a byte array.
.PARAMETER Sid
The SID to convert.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
ConvertFrom-NtSid -Sid "S-1-1-0"
Converts SID to byte array.
#>
function ConvertFrom-NtSid {
    [CmdletBinding(DefaultParameterSetName = "ToBytes")]
    Param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [NtCoreLib.Security.Authorization.Sid]$Sid
    )

    PROCESS {
        $Sid.ToArray() | Write-Output -NoEnumerate
    }
}

<#
.SYNOPSIS
Creates a new UserGroup object from SID and Attributes.
.DESCRIPTION
This cmdlet creates a new UserGroup object from SID and Attributes.
.PARAMETER Sid
List of SIDs to use to create object.
.PARAMETER Attribute
Common attributes for the new object.
.INPUTS
NtCoreLib.Security.Authorization.Sid[]
.OUTPUTS
NtCoreLib.Security.Token.UserGroup[]
.EXAMPLE
New-NtUserGroup -Sid "WD" -Attribute Enabled
Creates a new UserGroup with the World SID and the Enabled Flag.
#>
function New-NtUserGroup {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [NtCoreLib.Security.Authorization.Sid[]]$Sid,
        [NtCoreLib.GroupAttributes]$Attribute = 0
    )

    PROCESS {
        foreach ($s in $Sid) {
            New-Object NtCoreLib.Security.Token.UserGroup -ArgumentList $s, $Attribute
        }
    }
}

<#
.SYNOPSIS
Creates a new Object Type Tree object.
.DESCRIPTION
This cmdlet creates a new Object Type Tree object from a GUID. You can then use Add-ObjectTypeTree to
add more branches to the tree.
.PARAMETER ObjectType
Specify the Object Type GUID.
.PARAMETER Nodes
Specify a list of tree objects to add a children.
.PARAMETER Name
Optional name of the object type.
.PARAMETER SchemaObject
Specify to create from a schema object such as a schema class or extended right.
.INPUTS
None
.OUTPUTS
NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree
.EXAMPLE
$tree = New-ObjectTypeTree "bf967a86-0de6-11d0-a285-00aa003049e2"
Creates a new Object Type tree with the root type as 'bf967a86-0de6-11d0-a285-00aa003049e2'.
.EXAMPLE
$tree = New-ObjectTypeTree "bf967a86-0de6-11d0-a285-00aa003049e2" -Nodes $children
Creates a new Object Type tree with the root type as 'bf967a86-0de6-11d0-a285-00aa003049e2' with a list of children.
#>
function New-ObjectTypeTree {
    [CmdletBinding(DefaultParameterSetName="FromGuid")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromGuid")]
        [guid]$ObjectType,
        [Parameter(ParameterSetName = "FromGuid")]
        [NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree[]]$Nodes,
        [Parameter(ParameterSetName = "FromGuid")]
        [string]$Name = "",
        [parameter(Mandatory, ParameterSetName = "FromSchemaObject", Position = 0)]
        [NtCoreLib.Win32.DirectoryService.IDirectoryServiceObjectTree]$SchemaObject
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromGuid" {
            $tree = New-Object NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree -ArgumentList $ObjectType
            if ($null -ne $Nodes) {
                $tree.AddNodeRange($Nodes)
            }
            $tree.Name = $Name
            $tree
        }
        "FromSchemaObject" {
            ConvertTo-ObjectTypeTree -SchemaObject $SchemaObject
        }
    }
}

<#
.SYNOPSIS
Adds a new Object Type Tree node to an existing tree.
.DESCRIPTION
This cmdlet adds a new Object Type Tree object from a GUID to and existing tree.
.PARAMETER ObjectType
Specify the Object Type GUID to add.
.PARAMETER Tree
Specify the root tree to add to.
.PARAMETER Name
Optional name of the object type.
.PARAMETER PassThru
Specify to return the added tree.
.PARAMETER SchemaObject
Specify to add a schema object such as a schema class or extended right.
.INPUTS
None
.OUTPUTS
NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree
.EXAMPLE
Add-ObjectTypeTree $tree "bf967a86-0de6-11d0-a285-00aa003049e2"
Adds a new Object Type tree with the root type as 'bf967a86-0de6-11d0-a285-00aa003049e2'.
.EXAMPLE
Add-ObjectTypeTree $tree "bf967a86-0de6-11d0-a285-00aa003049e2" -Name "Property A"
Adds a new Object Type tree with the root type as 'bf967a86-0de6-11d0-a285-00aa003049e2'.
.EXAMPLE
Add-ObjectTypeTree $tree $obj
Adds a new Object Type tree based on a directory object.
#>
function Add-ObjectTypeTree {
    [CmdletBinding(DefaultParameterSetName="FromGuid")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree]$Tree,
        [Parameter(Position = 1, Mandatory, ParameterSetName = "FromGuid")]
        [guid]$ObjectType,
        [Parameter(ParameterSetName = "FromGuid")]
        [string]$Name = "",
        [parameter(Mandatory, ParameterSetName = "FromSchemaObject", Position = 1, ValueFromPipeline)]
        [NtCoreLib.Win32.DirectoryService.IDirectoryServiceObjectTree]$SchemaObject,
        [switch]$PassThru
    )

    PROCESS {
        $result = switch($PSCmdlet.ParameterSetName) {
            "FromGuid" {
                $r = $Tree.AddNode($ObjectType)
                $r.Name = $Name
                $r
            }
            "FromSchemaObject" {
                $r = ConvertTo-ObjectTypeTree -SchemaObject $SchemaObject
                $Tree.AddNode($r)
                $r
            }
        }
        if ($PassThru) {
            Write-Output $result
        }
    }
}

<#
.SYNOPSIS
Removes an Object Type Tree node.
.DESCRIPTION
This cmdlet removes a tree node.
.PARAMETER Tree
Specify the tree node to remove.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Remove-ObjectTypeTree $tree
Removes the tree node $tree from its parent.
#>
function Remove-ObjectTypeTree {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree]$Tree
    )
    $Tree.Remove()
}

<#
.SYNOPSIS
Sets an Object Type Tree's Remaining Access.
.DESCRIPTION
This cmdlet sets a Object Type Tree's remaining access as well as all its children.
.PARAMETER Tree
Specify tree node to set.
.PARAMETER Access
Specify the access to set.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-ObjectTypeTreeAccess $tree 0xFF
Sets the Remaning Access for this tree and all children to 0xFF.
#>
function Set-ObjectTypeTreeAccess {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree]$Tree,
        [Parameter(Position = 1, Mandatory)]
        [NtCoreLib.Security.Authorization.AccessMask]$Access
    )
    $Tree.SetRemainingAccess($Access)
}

<#
.SYNOPSIS
Revokes an Object Type Tree's Remaining Access.
.DESCRIPTION
This cmdlet revokes a Object Type Tree's remaining access as well as all its children.
.PARAMETER Tree
Specify tree node to revoke.
.PARAMETER Access
Specify the access to revoke.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Revoke-ObjectTypeTreeAccess $tree 0xFF
Revokes the Remaining Access of 0xFF for this tree and all children.
#>
function Revoke-ObjectTypeTreeAccess {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree]$Tree,
        [Parameter(Position = 1, Mandatory)]
        [NtCoreLib.Security.Authorization.AccessMask]$Access
    )
    $Tree.RemoveRemainingAccess($Access)
}

<#
.SYNOPSIS
Selects out an Object Type Tree node based on the object type.
.DESCRIPTION
This cmdlet selects out an Object Type Tree node based on the object type. Returns $null
if the Object Type can't be found.
.PARAMETER ObjectType
Specify the Object Type GUID to select
.PARAMETER Tree
Specify the tree to check.
.PARAMETER PassThru
Specify to return the added tree.
.INPUTS
None
.OUTPUTS
NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree
.EXAMPLE
Select-ObjectTypeTree $tree "bf967a86-0de6-11d0-a285-00aa003049e2"
Selects an Object Type tree with the type of 'bf967a86-0de6-11d0-a285-00aa003049e2'.
#>
function Select-ObjectTypeTree {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree]$Tree,
        [Parameter(Position = 1, Mandatory)]
        [guid]$ObjectType
    )
    
    $Tree.Find($ObjectType) | Write-Output
}


<#
.SYNOPSIS
Converts a DS object to an object type tree for access checking.
.DESCRIPTION
This cmdlet converts a DS object to an object type tree for access checking. This can be slow.
.PARAMETER DistinguishedName
Specify the distinguished name of the object.
.PARAMETER Object
Specify the object directory entry.
.PARAMETER Domain
Specify the domain or server name to query for the object. Defaults to current domain.
.PARAMETER SchemaObject
Specify an object convertable to the tree such as a schema object or extended right.
.INPUTS
None
.OUTPUTS
NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree
.EXAMPLE
ConvertTo-ObjectTypeTree -DistinguishedName "CN=Bob,CN=Users,DC=domain,DC=com"
Get the object type tree for a user object by name.
#>
function ConvertTo-ObjectTypeTree {
    [CmdletBinding(DefaultParameterSetName = "FromName")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromName", Position = 0)]
        [alias("dn")]
        [string]$DistinguishedName,
        [parameter(ParameterSetName = "FromName")]
        [string]$Domain,
        [parameter(Mandatory, ParameterSetName = "FromObject")]
        [System.DirectoryServices.DirectoryEntry]$Object,
        [parameter(Mandatory, ParameterSetName = "FromSchemaObject", ValueFromPipeline, Position = 0)]
        [NtCoreLib.Win32.DirectoryService.IDirectoryServiceObjectTree]$SchemaObject
    )

    PROCESS {
        $tree_obj = switch($PSCmdlet.ParameterSetName) {
            "FromName" {
               Get-DsObjectSchemaClass -Domain $Domain -Name $DistinguishedName
            }
            "FromObject" {
                Get-DsObjectSchemaClass -Object $Object
            }
            "FromSchemaObject" {
                $SchemaObject
            }
        }
        $tree_obj.ToObjectTypeTree()
    }
}

<#
.SYNOPSIS
Gets the Central Access Policy from the Registry.
.DESCRIPTION
This cmdlet gets the Central Access Policy from the Registry.
.PARAMETER FromLsa
Parse the Central Access Policy from LSA.
.PARAMETER CapId
Specify the CAPID SID to select.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.Policy.CentralAccessPolicy
.EXAMPLE
Get-CentralAccessPolicy
Gets the Central Access Policy from the Registry.
.EXAMPLE
Get-CentralAccessPolicy -FromLsa
Gets the Central Access Policy from the LSA.
#>
function Get-CentralAccessPolicy {
    Param(
        [Parameter(Position=0)]
        [NtCoreLib.Security.Authorization.Sid]$CapId,
        [switch]$FromLsa
    )
    $policy = if ($FromLsa) {
        [NtCoreLib.Security.Authorization.Policy.CentralAccessPolicy]::ParseFromLsa()
    }
    else {
        [NtCoreLib.Security.Authorization.Policy.CentralAccessPolicy]::ParseFromRegistry()
    }
    if ($null -eq $CapId) {
        $policy | Write-Output
    } else {
        $policy | Where-Object CapId -eq $CapId | Select-Object -First 1 | Write-Output
    }
}

<#
.SYNOPSIS
Get the advanced audit policy information.
.DESCRIPTION
This cmdlet gets advanced audit policy information.
.PARAMETER Category
Specify the category type.
.PARAMETER CategoryGuid
Specify the category type GUID.
.PARAMETER ExpandCategory
Specify to expand the subcategories from the category.
.PARAMETER User
Specify the user for a per-user Audit Policies.
.PARAMETER AllUser
Specify to get all users for all per-user Audit Policies.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Audit.AuditCategory
NtCoreLib.Win32.Security.Audit.AuditSubCategory
NtCoreLib.Win32.Security.Audit.AuditPerUserCategory
NtCoreLib.Win32.Security.Audit.AuditPerUserSubCategory
.EXAMPLE
Get-NtAuditPolicy
Get all audit policy categories.
.EXAMPLE
Get-NtAuditPolicy -Category ObjectAccess
Get the ObjectAccess audit policy category
.EXAMPLE
Get-NtAuditPolicy -Category ObjectAccess -Expand
Get the ObjectAccess audit policy category and return the SubCategory policies.
.EXAMPLE
Get-NtAuditPolicy -User $sid
Get all per-user audit policy categories for the user represented by a SID.
.EXAMPLE
Get-NtAuditPolicy -AllUser
Get all per-user audit policy categories for all users.
#>
function Get-NtAuditPolicy {
    [CmdletBinding(DefaultParameterSetName = "All")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromCategory")]
        [NtCoreLib.Win32.Security.Audit.AuditPolicyEventType[]]$Category,
        [parameter(Mandatory, ParameterSetName = "FromCategoryGuid")]
        [Guid[]]$CategoryGuid,
        [parameter(Mandatory, ParameterSetName = "FromSubCategoryName")]
        [string[]]$SubCategoryName,
        [parameter(Mandatory, ParameterSetName = "FromSubCategoryGuid")]
        [guid[]]$SubCategoryGuid,
        [parameter(ParameterSetName = "All")]
        [parameter(ParameterSetName = "FromCategory")]
        [parameter(ParameterSetName = "FromCategoryGuid")]
        [switch]$ExpandCategory,
        [parameter(ParameterSetName = "All")]
        [switch]$AllUser,
        [NtCoreLib.Security.Authorization.Sid]$User
    )

    $cats = switch ($PSCmdlet.ParameterSetName) {
        "All" {
            if ($null -ne $User) {
                [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::GetPerUserCategories($User)
            }
            elseif ($AllUser) {
                [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::GetPerUserCategories()
            }
            else {
                [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::GetCategories()
            }
        }
        "FromCategory" {
            $ret = @()
            foreach($cat in $Category) {
                if ($null -ne $User) {
                    $ret += [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::GetPerUserCategory($User, $cat)
                } else {
                    $ret += [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::GetCategory($cat)
                }
            }
            $ret
        }
        "FromCategoryGuid" {
            $ret = @()
            foreach($cat in $CategoryGuid) {
                if ($null -ne $User) {
                    $ret += [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::GetPerUserCategory($User, $cat)
                } else {
                    $ret += [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::GetCategory($cat)
                }
            }
            $ret
        }
        "FromSubCategoryName" {
            Get-NtAuditPolicy -ExpandCategory -User $User | Where-Object Name -in $SubCategoryName
        }
        "FromSubCategoryGuid" {
            Get-NtAuditPolicy -ExpandCategory -User $User | Where-Object Id -in $SubCategoryGuid
        }
    }
    if ($ExpandCategory) {
        $cats | Select-Object -ExpandProperty SubCategories | Write-Output
    } else {
        $cats | Write-Output
    }
}

<#
.SYNOPSIS
Set the advanced audit policy information.
.DESCRIPTION
This cmdlet sets advanced audit policy information.
.PARAMETER Category
Specify the category type.
.PARAMETER CategoryGuid
Specify the category type GUID.
.PARAMETER Policy
Specify the policy to set.
.PARAMETER PassThru
Specify to pass through the category objects.
.PARAMETER User
Specify the SID of the user to set a per-user audit policy.
.PARAMETER UserPolicy
Specify the policy to set for a per-user policy.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Audit.AuditSubCategory
NtCoreLib.Win32.Security.Audit.AuditPerUserSubCategory
.EXAMPLE
Set-NtAuditPolicy -Category 
Get all audit policy categories.
.EXAMPLE
Get-NtAuditPolicy -Category ObjectAccess
Get the ObjectAccess audit policy category
.EXAMPLE
Get-NtAuditPolicy -Category ObjectAccess -Expand
Get the ObjectAccess audit policy category and return the SubCategory policies.
#>
function Set-NtAuditPolicy {
    [CmdletBinding(DefaultParameterSetName = "FromCategoryType", SupportsShouldProcess)]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromCategoryType")]
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromCategoryTypeUser")]
        [NtCoreLib.Win32.Security.Audit.AuditPolicyEventType[]]$Category,
        [parameter(Mandatory, ParameterSetName = "FromCategoryGuid")]
        [parameter(Mandatory, ParameterSetName = "FromCategoryGuidUser")]
        [Guid[]]$CategoryGuid,
        [parameter(Mandatory, ParameterSetName = "FromSubCategoryName")]
        [parameter(Mandatory, ParameterSetName = "FromSubCategoryNameUser")]
        [string[]]$SubCategoryName,
        [parameter(Mandatory, ParameterSetName = "FromSubCategoryGuid")]
        [parameter(Mandatory, ParameterSetName = "FromSubCategoryUser")]
        [guid[]]$SubCategoryGuid,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromCategoryType")]
        [parameter(Mandatory, Position = 1, ParameterSetName="FromCategoryGuid")]
        [parameter(Mandatory, Position = 1, ParameterSetName="FromSubCategoryName")]
        [parameter(Mandatory, Position = 1, ParameterSetName="FromSubCategoryGuid")]
        [NtCoreLib.Win32.Security.Audit.AuditPolicyFlags]$Policy,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromCategoryTypeUser")]
        [parameter(Mandatory, Position = 1, ParameterSetName="FromCategoryGuidUser")]
        [parameter(Mandatory, Position = 1, ParameterSetName="FromSubCategoryNameUser")]
        [parameter(Mandatory, Position = 1, ParameterSetName="FromSubCategoryGuidUser")]
        [NtCoreLib.Win32.Security.Audit.AuditPerUserPolicyFlags]$UserPolicy,
        [parameter(Mandatory, ParameterSetName="FromCategoryTypeUser")]
        [parameter(Mandatory, ParameterSetName="FromCategoryGuidUser")]
        [parameter(Mandatory, ParameterSetName="FromSubCategoryNameUser")]
        [parameter(Mandatory, ParameterSetName="FromSubCategoryGuidUser")]
        [NtCoreLib.Security.Authorization.Sid]$User,
        [switch]$PassThru
    )
    if (!(Test-NtTokenPrivilege SeSecurityPrivilege)) {
        Write-Warning "SeSecurityPrivilege not enabled. Might not change Audit settings."
    }

    $cats = switch -Wildcard ($PSCmdlet.ParameterSetName) {
        "FromCategoryType*" {
            Get-NtAuditPolicy -Category $Category -ExpandCategory -User $User
        }
        "FromCategoryGuid*" {
            Get-NtAuditPolicy -CategoryGuid $CategoryGuid -ExpandCategory -User $User
        }
        "FromSubCategoryName*" {
            Get-NtAuditPolicy -SubCategoryName $SubCategoryName -User $User
        }
        "FromSubCategoryGuid*" {
            Get-NtAuditPolicy -SubCategoryGuid $SubCategoryGuid -User $User
        }
    }

    foreach($cat in $cats) {
        $policy_value = if ($null -eq $User) {
            $Policy
        }
        else {
            $UserPolicy
        }
        if ($PSCmdlet.ShouldProcess($cat.Name, "Set $policy_value")) {
            $cat.SetPolicy($policy_value)
            if ($PassThru) {
                Write-Output $cat
            }
        }
    }
}

<#
.SYNOPSIS
Get advanced audit policy security descriptor information.
.DESCRIPTION
This cmdlet gets advanced audit policy security descriptor information.
.PARAMETER GlobalSacl
Specify the type of object to query the global SACL.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.SecurityDescriptor
.EXAMPLE
Get-NtAuditSecurity
Get the Audit security descriptor.
.EXAMPLE
Get-NtAuditSecurity -GlobalSacl File
Get the File global SACL.
#>
function Get-NtAuditSecurity {
    [CmdletBinding(DefaultParameterSetName = "FromSecurityDescriptor")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromGlobalSacl")]
        [NtCoreLib.Win32.Security.Audit.AuditGlobalSaclType]$GlobalSacl
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromSecurityDescriptor" {
            [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::QuerySecurity() | Write-Output
        }
        "FromGlobalSacl" {
            [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::QueryGlobalSacl($GlobalSacl) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Set advanced audit policy security descriptor information.
.DESCRIPTION
This cmdlet sets advanced audit policy security descriptor information.
.PARAMETER GlobalSacl
Specify the type of object to set the global SACL.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-NtAuditSecurity -SecurityDescriptor $sd
Set the Audit security descriptor.
.EXAMPLE
Set-NtAuditSecurity -SecurityDescriptor $sd -GlobalSacl File
Set the File global SACL.
#>
function Set-NtAuditSecurity {
    [CmdletBinding(DefaultParameterSetName = "FromSecurityDescriptor", SupportsShouldProcess)]
    param (
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [parameter(Mandatory, Position = 1, ParameterSetName = "FromGlobalSacl")]
        [NtCoreLib.Win32.Security.Audit.AuditGlobalSaclType]$GlobalSacl
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromSecurityDescriptor" {
            if ($PSCmdlet.ShouldProcess("$SecurityDescriptor", "Set Audit SD")) {
                [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::SetSecurity("Dacl", $SecurityDescriptor)
            }
        }
        "FromGlobalSacl" {
            if ($PSCmdlet.ShouldProcess("$SecurityDescriptor", "Set $GlobalSacl SACL")) {
                [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::SetGlobalSacl($GlobalSacl, $SecurityDescriptor)
            }
        }
    }
}

<#
.SYNOPSIS
Get account rights for current system.
.DESCRIPTION
This cmdlet gets account rights for the current system.
.PARAMETER Type
Specify the type of account rights to query.
.PARAMETER Sid
Specify a SID to get all account rights for.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Policy.AccountRight
.EXAMPLE
Get-NtAccountRight
Get all account rights.
.EXAMPLE
Get-NtAccountRight -Type Privilege
Get all privilege account rights.
.EXAMPLE
Get-NtAccountRight -Type Logon
Get all logon account rights.
.EXAMPLE
Get-NtAccountRight -SID $sid
Get account rights for SID.
.EXAMPLE
Get-NtAccountRight -KnownSid World
Get account rights for known SID.
.EXAMPLE
Get-NtAccountRight -Name "Everyone"
Get account rights for group name.
#>
function Get-NtAccountRight {
    [CmdletBinding(DefaultParameterSetName = "All")]
    param (
        [parameter(Position = 0, ParameterSetName = "All")]
        [NtCoreLib.Win32.Security.Policy.AccountRightType]$Type = "All",
        [parameter(Mandatory, ParameterSetName = "FromSid")]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [parameter(Mandatory, ParameterSetName = "FromKnownSid")]
        [NtCoreLib.Security.Authorization.KnownSidValue]$KnownSid,
        [parameter(Mandatory, ParameterSetName = "FromName")]
        [string]$Name
    )

    switch($PSCmdlet.ParameterSetName) {
        "All" {
            [NtCoreLib.Win32.Security.Win32Security]::GetAccountRights($Type) | Write-Output
        }
        "FromSid" {
            [NtCoreLib.Win32.Security.Win32Security]::GetAccountRights($Sid) | Write-Output
        }
        "FromKnownSid" {
            [NtCoreLib.Win32.Security.Win32Security]::GetAccountRights((Get-NtSid -KnownSid $KnownSid)) | Write-Output
        }
        "FromName" {
            [NtCoreLib.Win32.Security.Win32Security]::GetAccountRights((Get-NtSid -Name $Name)) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Add account rights for current system.
.DESCRIPTION
This cmdlet adds account rights for the current system to a SID.
.PARAMETER Sid
Specify a SID to add the account right for.
.PARAMETER Privilege
Specify the privileges to add.
.PARAMETER Name
Specify the list of account right names to add.
.PARAMETER LogonType
Specify the list of logon types to add.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Add-NtAccountRight -Sid WD -Privilege SeAssignPrimaryTokenPrivilege
Add everyone group to SeAssignPrimaryTokenPrivilege
#>
function Add-NtAccountRight {
    [CmdletBinding(DefaultParameterSetName = "FromPrivs")]
    param (
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [parameter(Mandatory, ParameterSetName = "FromPrivs")]
        [NtCoreLib.Security.Token.TokenPrivilegeValue[]]$Privilege,
        [parameter(Mandatory, ParameterSetName = "FromString")]
        [string[]]$Name,
        [parameter(Mandatory, ParameterSetName = "FromLogonType")]
        [NtCoreLib.Win32.Security.Policy.AccountRightLogonType[]]$LogonType
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromString" {
            [NtCoreLib.Win32.Security.Win32Security]::AddAccountRights($Sid, $Name)
        }
        "FromPrivs" {
            [NtCoreLib.Win32.Security.Win32Security]::AddAccountRights($Sid, $Privilege)
        }
        "FromLogonType" {
            [NtCoreLib.Win32.Security.Win32Security]::AddAccountRights($Sid, $LogonType)
        }
    }
}

<#
.SYNOPSIS
Remove account rights for current system.
.DESCRIPTION
This cmdlet removes account rights for the current system from a SID.
.PARAMETER Sid
Specify a SID to remove the account right for.
.PARAMETER Privilege
Specify the privileges to remove.
.PARAMETER Name
Specify the list of account right names to remove.
.PARAMETER LogonType
Specify the list of logon types to remove.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Remove-NtAccountRight -Sid WD -Privilege SeAssignPrimaryTokenPrivilege
Remove everyone group from SeAssignPrimaryTokenPrivilege
#>
function Remove-NtAccountRight {
    [CmdletBinding(DefaultParameterSetName = "FromPrivs")]
    param (
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [parameter(Mandatory, ParameterSetName = "FromPrivs")]
        [NtCoreLib.Security.Token.TokenPrivilegeValue[]]$Privilege,
        [parameter(Mandatory, ParameterSetName = "FromString")]
        [string[]]$Name,
        [parameter(Mandatory, ParameterSetName = "FromLogonType")]
        [NtCoreLib.Win32.Security.Policy.AccountRightLogonType[]]$LogonType
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromString" {
            [NtCoreLib.Win32.Security.Win32Security]::RemoveAccountRights($Sid, $Name)
        }
        "FromPrivs" {
            [NtCoreLib.Win32.Security.Win32Security]::RemoveAccountRights($Sid, $Privilege)
        }
        "FromLogonType" {
            [NtCoreLib.Win32.Security.Win32Security]::RemoveAccountRights($Sid, $LogonType)
        }
    }
}

<#
.SYNOPSIS
Get SIDs for an account right for current system.
.DESCRIPTION
This cmdlet gets SIDs for an account rights for the current system.
.PARAMETER Privilege
Specify a privileges to query.
.PARAMETER Logon
Specify a logon rights to query.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.Sid
.EXAMPLE
Get-NtAccountRightSid -Privilege SeBackupPrivilege
Get all SIDs for SeBackupPrivilege.
.EXAMPLE
Get-NtAccountRightSid -Logon SeInteractiveLogonRight
Get all SIDs which can logon interactively.
#>
function Get-NtAccountRightSid {
    [CmdletBinding(DefaultParameterSetName = "Privilege")]
    param (
        [parameter(Mandatory, ParameterSetName = "FromPrivilege")]
        [NtCoreLib.Security.Token.TokenPrivilegeValue]$Privilege,
        [parameter(Mandatory, ParameterSetName = "FromLogon")]
        [NtCoreLib.Win32.Security.Policy.AccountRightLogonType]$Logon
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromPrivilege" {
            [NtCoreLib.Win32.Security.Win32Security]::GetAccountRightSids($Privilege) | Write-Output
        }
        "FromLogon" {
            [NtCoreLib.Win32.Security.Win32Security]::GetAccountRightSids($Logon) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Add a SID to name mapping.
.DESCRIPTION
This cmdlet adds a SID to name mapping. You can also add the name to LSASS if you have SeTcbPrivilege
and the SID meets specific requirements.
.PARAMETER Sid
Specify the SID to add.
.PARAMETER Domain
Specify the domain name to add. When adding a cache this is optional. For register this is required.
.PARAMETER Name
Specify the name to add. For register this is optional.
.PARAMETER NameUse
Specify the name to use type.
.PARAMETER Register
Register SID name with LSASS.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Add-NtSidName -Sid S-1-2-3-4-5 -Domain ABC -User XYZ
Add a SID name.
.EXAMPLE
Add-NtSidName -Sid S-1-5-101-0 -Domain ABC -User XYZ -Register
Add a SID name and register with LSASS.
#>
function Add-NtSidName {
    [CmdletBinding(DefaultParameterSetName="FromName")]
    param (
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromName")]
        [parameter(Position = 2, ParameterSetName="RegisterSid")]
        [string]$Name,
        [parameter(Position = 2, ParameterSetName="FromName")]
        [parameter(Mandatory, Position = 1, ParameterSetName="RegisterSid")]
        [string]$Domain,
        [parameter(Position = 3, ParameterSetName="FromName")]
        [NtCoreLib.Security.Authorization.SidNameUse]$NameUse = "Group",
        [parameter(Mandatory, ParameterSetName="RegisterSid")]
        [switch]$Register
    )

    if ($Register) {
        [NtCoreLib.Win32.Security.Win32Security]::AddSidNameMapping($Domain, $Name, $Sid)
    } else {
        [NtCoreLib.Security.NtSecurity]::AddSidName($Sid, $Domain, $Name, $NameUse)
    }
}

<#
.SYNOPSIS
Add a SID to name mapping.
.DESCRIPTION
This cmdlet adds a SID to name mapping. You can also add the name to LSASS if you have SeTcbPrivilege
and the SID meets specific requirements.
.PARAMETER Sid
Specify an API set name to lookup.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Remove-NtSidName -Sid S-1-2-3-4-5
Remove a SID name.
.EXAMPLE
Remove-NtSidName -Sid S-1-5-101-0 -Unregister
Remove a SID name and unregister with LSASS.
#>
function Remove-NtSidName {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [switch]$Unregister
    )

    if ($Unregister) {
        [NtCoreLib.Win32.Security.Win32Security]::RemoveSidNameMapping($Sid)
    }
    [NtCoreLib.Security.NtSecurity]::RemoveSidName($Sid)
}

<#
.SYNOPSIS
Clear the SID to name cache.
.DESCRIPTION
This cmdlet clears the SID to name cache.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Clear-NtSidName
Clears the SID to name cache.
#>
function Clear-NtSidName {
    [NtCoreLib.Security.NtSecurity]::ClearSidNameCache()
}

<#
.SYNOPSIS
Get the name for a SID.
.DESCRIPTION
This cmdlet looks up a name for a SID and returns the name with a source for where the name came from.
.PARAMETER Sid
The SID to lookup the name for.
.PARAMETER BypassCache
Specify to bypass the name cache for this lookup.
.INPUTS
NtCoreLib.Security.Authorization.Sid[]
.OUTPUTS
NtCoreLib.Security.Authorization.SidName
.EXAMPLE
Get-NtSidName "S-1-1-0"
Lookup the name for the SID S-1-1-0.
.EXAMPLE
Get-NtSidName "S-1-1-0" -BypassCache
Lookup the name for the SID S-1-1-0 without checking the name cache.
#>
function Get-NtSidName {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [switch]$BypassCache
    )

    PROCESS {
        $Sid.GetName($BypassCache)
    }
}

<#
.SYNOPSIS
Test properties of a SID.
.DESCRIPTION
This cmdlet tests the SID for various different properties such as whether it's a capability SID.
.PARAMETER Sid
The SID to test.
.PARAMETER Integrity
Specify to check if the SID is an integrity SID.
.PARAMETER Capability
Specify to check if the SID is a capability SID.
.PARAMETER CapabilityGroup
Specify to check if the SID is a capability group SID.
.PARAMETER Service
Specify to check if the SID is a service SID.
.PARAMETER LogonSession
Specify to check if the SID is a logon session SID.
.PARAMETER ProcessTrust
Specify to check if the SID is a process trust SID.
.PARAMETER Domain
Specify to check if the SID is a domain SID.
.PARAMETER LocalDomain
Specify to check if the SID is the local domain SID.
.INPUTS
NtCoreLib.Security.Authorization.Sid[]
.OUTPUTS
bool
.EXAMPLE
Test-NtSid "S-1-16-12288" -IsIntegrity
Checks if the SID is an integrity SID.
#>
function Test-NtSid {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [parameter(Mandatory, ParameterSetName="Integrity")]
        [switch]$Integrity,
        [parameter(Mandatory, ParameterSetName="Capability")]
        [switch]$Capability,
        [parameter(Mandatory, ParameterSetName="CapabilityGroup")]
        [switch]$CapabilityGroup,
        [parameter(Mandatory, ParameterSetName="Service")]
        [switch]$Service,
        [parameter(Mandatory, ParameterSetName="LogonSession")]
        [switch]$LogonSession,
        [parameter(Mandatory, ParameterSetName="ProcessTrust")]
        [switch]$ProcessTrust,
        [parameter(Mandatory, ParameterSetName="Domain")]
        [switch]$Domain,
        [parameter(Mandatory, ParameterSetName="LocalDomain")]
        [switch]$LocalDomain
    )

    PROCESS {
        switch($PSCmdlet.ParameterSetName) {
            "Integrity" {
                [NtCoreLib.Security.NtSecurity]::IsIntegritySid($Sid)
            }
            "Capability" {
                [NtCoreLib.Security.NtSecurity]::IsCapabilitySid($Sid)
            }
            "CapabilityGroup" {
                [NtCoreLib.Security.NtSecurity]::IsCapabilityGroupSid($Sid)
            }
            "Service" {
                [NtCoreLib.Security.NtSecurity]::IsServiceSid($Sid)
            }
            "LogonSession" {
                [NtCoreLib.Security.NtSecurity]::IsLogonSessionSid($Sid)
            }
            "ProcessTrust" {
                [NtCoreLib.Security.NtSecurity]::IsProcessTrustSid($Sid)
            }
            "Domain" {
                [NtCoreLib.Security.NtSecurity]::IsDomainSid($Sid)
            }
            "LocalDomain" {
                [NtCoreLib.Security.NtSecurity]::IsLocalDomainSid($Sid)
            }
        }
    }
}

<#
.SYNOPSIS
Create a kernel crash dump.
.DESCRIPTION
This cmdlet will use the NtSystemDebugControl API to create a system kernel crash dump with specified options.
.PARAMETER Path
The NT native path to the crash dump file to create
.PARAMETER Flags
Optional flags to control what to dump
.PARAMETER PageFlags
Optional flags to control what additional pages to dump
.INPUTS
None
.EXAMPLE
New-NtKernelCrashDump \??\C:\memory.dmp
Create a new crash dump at c:\memory.dmp
.EXAMPLE
New-NtKernelCrashDump \??\C:\memory.dmp -Flags IncludeUserSpaceMemoryPages
Create a new crash dump at c:\memory.dmp including user memory pages.
#>
function New-NtKernelCrashDump {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Path,
        [NtCoreLib.SystemDebugKernelDumpControlFlags]$Flags = 0,
        [NtCoreLib.SystemDebugKernelDumpPageControlFlags]$PageFlags = 0
    )
    [NtCoreLib.NtSystemInfo]::CreateKernelDump($Path, $Flags, $PageFlags)
}

<#
.SYNOPSIS
Get a range of system information values.
.DESCRIPTION
This cmdlet gets a range of system information values.
.PARAMETER IsolatedUserMode
Return isolated usermode flags.
.PARAMETER ProcessorInformation
Return processor information.
.PARAMETER MultiSession
Return whether this system is a multi-session SKU.
.PARAMETER MultiSession
Return the system's elevation flags.
.INPUTS
None
.OUTPUTS
Depends on parameters.
.EXAMPLE
Get-NtSystemInformation -IsolatedUserMode
Get isolated user mode information.
#>
function Get-NtSystemInformation {
    param(
        [Parameter(Mandatory, ParameterSetName="IsolatedUserMode")]
        [switch]$IsolatedUserMode,
        [Parameter(Mandatory, ParameterSetName="ProcessorInformation")]
        [switch]$ProcessorInformation,
        [Parameter(Mandatory, ParameterSetName="MultiSession")]
        [switch]$MultiSession,
        [Parameter(Mandatory, ParameterSetName="Elevation")]
        [switch]$ElevationFlags
    )
    if ($IsolatedUserMode) {
        [NtCoreLib.NtSystemInfo]::IsolatedUserModeFlags
    } elseif ($ProcessorInformation) {
        [NtCoreLib.NtSystemInfo]::ProcessorInformation
    } elseif ($MultiSession) {
        [NtCoreLib.NtSystemInfo]::IsMultiSession
    } elseif ($ElevationFlags) {
        [NtCoreLib.NtSystemInfo]::ElevationFlags
    }
}

<#
.SYNOPSIS
Get list of loaded kernel modules.
.DESCRIPTION
This cmdlet gets the list of loaded kernel modules.
.INPUTS
None
.OUTPUTS
NtCoreLib.Kernel.Process.ProcessModule[]
#>
function Get-NtKernelModule {
    [NtCoreLib.NtSystemInfo]::GetKernelModules() | Write-Output
}

<#
.SYNOPSIS
Get logon sessions for current system.
.DESCRIPTION
This cmdlet gets the active logon sessions for the current system.
.PARAMETER LogonId
Specify the Logon ID for the session.
.PARAMETER Token
Specify a Token to get the session for.
.PARAMETER IdOnly
Specify to only get the Logon ID rather than full details.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.LogonSession
NtCoreLib.Luid
.EXAMPLE
Get-NtLogonSession
Get all accessible logon sessions.
.EXAMPLE
Get-NtLogonSession -LogonId 123456
Get logon session with ID 123456
.EXAMPLE
Get-NtLogonSession -Token $token
Get logon session from Token Authentication ID.
.EXAMPLE
Get-NtLogonSession -IdOnly
Get all logon sesion IDs only.
#>
function Get-NtLogonSession {
    [CmdletBinding(DefaultParameterSetName = "All")]
    param (
        [parameter(Mandatory, ParameterSetName = "FromLogonId")]
        [NtCoreLib.Luid]$LogonId,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromToken")]
        [NtCoreLib.NtToken]$Token,
        [parameter(ParameterSetName = "All")]
        [switch]$IdOnly
    )
    switch($PSCmdlet.ParameterSetName) {
        "All" {
            if ($IdOnly) {
                [NtCoreLib.Win32.Security.Win32Security]::GetLogonSessionIds() | Write-Output
            } else {
                [NtCoreLib.Win32.Security.Win32Security]::GetLogonSessions() | Write-Output
            }
        }
        "FromLogonId" {
            [NtCoreLib.Win32.Security.Win32Security]::GetLogonSession($LogonId) | Write-Output
        }
        "FromToken" {
            [NtCoreLib.Win32.Security.Win32Security]::GetLogonSession($Token.AuthenticationId) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get current console sessions for the system.
.DESCRIPTION
This cmdlet gets current console sessions for the system.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.TerminalServices.ConsoleSession
.EXAMPLE
Get-NtConsoleSession
Get all Console Sesssions.
#>
function Get-NtConsoleSession {
    [NtCoreLib.Win32.TerminalServices.TerminalServicesUtils]::GetConsoleSessions() | Write-Output
}

<#
.SYNOPSIS
Gets a new Locally Unique ID (LUID)
.DESCRIPTION
This cmdlet requests a new LUID value.
.INPUTS
None
.OUTPUTS
NtCoreLib.Luid
.EXAMPLE
Get-NtLocallyUniqueId
Get a new locally unique ID.
#>
function Get-NtLocallyUniqueId {
    [NtCoreLib.NtSystemInfo]::AllocateLocallyUniqueId() | Write-Output
}

<#
.SYNOPSIS
Gets the access masks for a type.
.DESCRIPTION
This cmdlet gets the access masks for a type.
.PARAMETER Type
The NT type.
.PARAMETER Read
Show only read access.
.PARAMETER Write
Show only write access.
.PARAMETER Execute
Show only execute access.
.PARAMETER Mandatory
Show only default mandatory access.
.PARAMETER SpecificOnly
Show only type specific access.
.INPUTS
None
.OUTPUTS
AccessMask entries.
#>
function Get-NtTypeAccess {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtType]$Type,
        [Parameter(ParameterSetName = "Read")]
        [switch]$Read,
        [Parameter(ParameterSetName = "Write")]
        [switch]$Write,
        [Parameter(ParameterSetName = "Execute")]
        [switch]$Execute,
        [Parameter(ParameterSetName = "Mandatory")]
        [switch]$Mandatory,
        [switch]$SpecificOnly
    )

    $access = switch ($PSCmdlet.ParameterSetName) {
        "All" { $Type.AccessRights }
        "Read" { $Type.ReadAccessRights }
        "Write" { $Type.WriteAccessRights }
        "Execute" { $Type.ExecuteAccessRights }
        "Mandatory" { $Type.MandatoryAccessRights }
    }

    if ($SpecificOnly) {
        $access | Where-Object {$_.Mask.HasSpecificAccess} | Write-Output
    } else {
        $access | Write-Output
    }
}

<#
.SYNOPSIS
Creates a new "fake" NT type object.
.DESCRIPTION
This cmdlet creates a new "fake" NT type object which can be used to do access checking for objects which aren't real NT types.
.PARAMETER Name
The name of the "fake" type.
.PARAMETER GenericRead
The value of GenericRead for the GENERIC_MAPPING.
.PARAMETER GenericWrite
The value of GenericWrite for the GENERIC_MAPPING.
.PARAMETER GenericExecute
The value of GenericExecute for the GENERIC_MAPPING.
.PARAMETER GenericAll
The value of GenericAll for the GENERIC_MAPPING.
.PARAMETER AccessRightsType
The enumerated type.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtType
#>
function New-NtType {
    Param(
        [parameter(Position = 0, Mandatory)]
        [string]$Name,
        [System.Type]$AccessRightsType = [NtCoreLib.GenericAccessRights],
        [NtCoreLib.Security.Authorization.AccessMask]$GenericRead = 0,
        [NtCoreLib.Security.Authorization.AccessMask]$GenericWrite = 0,
        [NtCoreLib.Security.Authorization.AccessMask]$GenericExecute = 0,
        [NtCoreLib.Security.Authorization.AccessMask]$GenericAll = 0
    )

    [NtCoreLib.NtType]::GetFakeType($Name, $GenericRead, $GenericWrite, $GenericExecute, $GenericAll, $AccessRightsType)
}

<#
.SYNOPSIS
Suspend a thread.
.DESCRIPTION
This cmdlet suspends a thread.
.PARAMETER Process
The thread to suspend.
.INPUTS
NtCoreLib.NtThread
.OUTPUTS
None
#>
function Suspend-NtThread {
    [CmdletBinding(DefaultParameterSetName = "FromThread")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromThread", ValueFromPipeline)]
        [NtCoreLib.NtThread[]]$Thread
    )

    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "FromThread" {
                foreach ($t in $Thread) {
                    $t.Suspend() | Out-Null
                }
            }
        }
    }
}

<#
.SYNOPSIS
Resume a thread.
.DESCRIPTION
This cmdlet resumes a thread.
.PARAMETER Process
The thread to resume.
.INPUTS
NtCoreLib.NtThread
.OUTPUTS
None
#>
function Resume-NtThread {
    [CmdletBinding(DefaultParameterSetName = "FromThread")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromThread", ValueFromPipeline)]
        [NtCoreLib.NtThread[]]$Thread
    )

    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "FromThread" {
                foreach ($t in $Thread) {
                    $t.Resume() | Out-Null
                }
            }
        }
    }
}

<#
.SYNOPSIS
Stop a thread.
.DESCRIPTION
This cmdlet stops/kills a thread with an optional status code.
.PARAMETER Process
The thread to stop.
.INPUTS
NtCoreLib.NtThread
.OUTPUTS
None
#>
function Stop-NtThread {
    [CmdletBinding(DefaultParameterSetName = "FromThread")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromThread", ValueFromPipeline)]
        [NtCoreLib.NtThread[]]$Thread,
        [NtCoreLib.NtStatus]$ExitCode = 0
    )

    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "FromThread" {
                foreach ($t in $Thread) {
                    $t.Terminate($ExitCode)
                }
            }
        }
    }
}

<#
.SYNOPSIS
Query the context for a thread.
.DESCRIPTION
This cmdlet queries the context for a thread.
.PARAMETER Thread
Specify the thread to get the context for.
.PARAMETER ContextFlags
Specify the parts of the context to query.
.INPUTS
None
.OUTPUTS
NtCoreLib.IContext
.EXAMPLE
Get-NtThreadContext -Thread $thread
Query the thread's context for all state.
#>
function Get-NtThreadContext {
    param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtThread]$Thread,
        [NtCoreLib.ContextFlags]$ContextFlags = "All"
    )
    $Thread.GetContext($ContextFlags)
}

<#
.SYNOPSIS
Set the context for a thread.
.DESCRIPTION
This cmdlet sets the context for a thread.
.PARAMETER Thread
Specify the thread to set the context for.
.PARAMETER Context
Specify the context to set. You must configure the ContextFlags to determine what parts to set.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-NtThreadContext -Thread $thread -Context $context
Sets the thread's context.
#>
function Set-NtThreadContext {
    param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtThread]$Thread,
        [parameter(Mandatory, Position = 1)]
        [NtCoreLib.IContext]$Context
    )
    $Thread.SetContext($Context)
}

<#
.SYNOPSIS
Gets a work-on-behalf ticket for a thread.
.DESCRIPTION
This cmdlet gets the work-on-behalf ticket for a thread. 
.PARAMETER Thread
Specify a thread to get the ticket from.
.INPUTS
None
.OUTPUTS
NtCoreLib.WorkOnBehalfTicket
.EXAMPLE
Get-NtThreadWorkOnBehalfTicket
Get the work-on-behalf ticket for the current thread.
.EXAMPLE
Get-NtThreadWorkOnBehalfTicket -Thread $thread
Get the work-on-behalf ticket for a thread.
#>
function Get-NtThreadWorkOnBehalfTicket {
    param(
        [parameter(Position = 0)]
        [NtCoreLib.NtThread]$Thread
    )
    if ($Thread -eq $null) {
        [NtCoreLib.NtThread]::WorkOnBehalfTicket
    } else {
        $Thread.GetWorkOnBehalfTicket()
    }
}

<#
.SYNOPSIS
Set a work-on-behalf ticket on the current thread.
.DESCRIPTION
This cmdlet gets the work-on-behalf ticket for a thread. 
.PARAMETER Ticket
Specify the ticket to set.
.PARAMETER ThreadId
Specify the thread ID to set.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-NtThreadWorkOnBehalfTicket -Ticket $ticket
Set the work-on-behalf ticket for the current thread.
#>
function Set-NtThreadWorkOnBehalfTicket {
    [CmdletBinding(DefaultParameterSetName = "FromTicket")]
    param(
        [parameter(Mandatory, Position = 0, ParameterSetName="FromTicket")]
        [NtCoreLib.WorkOnBehalfTicket]$Ticket,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromThreadId")]
        [alias("tid")]
        [int]$ThreadId
    )
    if ($PSCmdlet.ParameterSetName -eq 'FromThreadId') {
        [NtCoreLib.NtThread]::SetWorkOnBehalfTicket($ThreadId)
    } else {
        [NtCoreLib.NtThread]::WorkOnBehalfTicket = $Ticket
    }
}

<#
.SYNOPSIS
Clear the work-on-behalf ticket on the current thread.
.DESCRIPTION
This cmdlet clears the work-on-behalf ticket for a thread. 
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Clear-NtThreadWorkOnBehalfTicket
Clear the work-on-behalf ticket for the current thread.
#>
function Clear-NtThreadWorkOnBehalfTicket {
    $ticket = [NtCoreLib.WorkOnBehalfTicket]::new(0)
    [NtCoreLib.NtThread]::WorkOnBehalfTicket = $ticket
}

<#
.SYNOPSIS
Gets the container ID for the current thread.
.DESCRIPTION
This cmdlet gets the container ID for the current thread thread.
.INPUTS
None
.OUTPUTS
Guid
.EXAMPLE
Get-NtThreadContainerId
Get the container ID for the current thread.
#>
function Get-NtThreadContainerId {
    [NtCoreLib.NtThread]::Current.ContainerId
}

<#
.SYNOPSIS
Attaches a container to impersonate the current thread.
.DESCRIPTION
This cmdlet attaches a container for impersonation on the current thread.
.PARAMETER Job
The job silo to set as the thread's container.
.INPUTS
None
.OUTPUTS
NtCoreLib.Utilities.Token.ThreadImpersonationContext
.EXAMPLE
$imp = Set-NtThreadContainer -Job $job
Sets the container for the current thread.
#>
function Set-NtThreadContainer {
    param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtJob]$Job
    )
    [NtCoreLib.NtThread]::AttachContainer($Job)
}

<#
.SYNOPSIS
Duplicates a token to a new token.
.DESCRIPTION
This cmdlet duplicates a token to another with specified
.PARAMETER Token
Specify the token to duplicate. If not specified will use the current process token.
.PARAMETER ImpersonationLevel
If specified will duplicate the token as an impersonation token.
.PARAMETER Primary
If specified will duplicate the token as a primary token.
.PARAMETER Access
Specify the access to the new token object.
.PARAMETER Inherit
Specify the token handle is inheritable.
.PARAMETER SecurityDescriptor
Specify the new token's security descriptor.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtToken
.EXAMPLE
Copy-NtToken -Primary
Copy the current token as a primary token.
.EXAMPLE
Copy-NtToken -ImpersonationLevel Impersonation
Copy the current token as a primary token.
.EXAMPLE
Copy-NtToken -Primary -Token $token
Copy an existing token as a primary token.
#>
function Copy-NtToken {
    [CmdletBinding(DefaultParameterSetName = "Impersonation")]
    Param(
        [NtCoreLib.NtToken]$Token,
        [parameter(Mandatory, ParameterSetName = "Impersonation", Position = 0)]
        [NtCoreLib.Security.Token.SecurityImpersonationLevel]$ImpersonationLevel,
        [parameter(Mandatory, ParameterSetName = "Primary")]
        [switch]$Primary,
        [NtCoreLib.TokenAccessRights]$Access = "MaximumAllowed",
        [switch]$Inherit,
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
    )

    switch ($PSCmdlet.ParameterSetName) {
        "Impersonation" {
            $tokentype = "Impersonation"
        }
        "Primary" {
            $tokentype = "Primary"
            $ImpersonationLevel = "Anonymous"
        }
    }

    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective
    }
    else {
        $Token = $Token.Duplicate()
    }

    $attributes = "None"
    if ($Inherit) {
        $attributes = "Inherit"
    }

    Use-NtObject($Token) {
        $Token.DuplicateToken($tokentype, $ImpersonationLevel, $Access, $attributes, $SecurityDescriptor)
    }
}

<#
.SYNOPSIS
Get a token's ID values.
.DESCRIPTION
This cmdlet will get Token's ID values such as Authentication ID and Origin ID.
.PARAMETER Authentication
Specify to get authentication Id.
.PARAMETER Origin
Specify to get origin Id.
.PARAMETER Modified
Specify to get modified Id.
.PARAMETER Token
Optional token object to use to get ID. Must be accesible for Query right.
.INPUTS
None
.OUTPUTS
NtCoreLib.Luid
.EXAMPLE
Get-NtTokenId
Get the Token ID field.
.EXAMPLE
Get-NtTokenId -Token $token
Get Token ID on an explicit token object.
.EXAMPLE
Get-NtTokenId -Authentication
Get the token's Authentication ID.
.EXAMPLE
Get-NtTokenId -Origin
Get the token's Origin ID.
#>
function Get-NtTokenId {
    [CmdletBinding(DefaultParameterSetName="FromId")]
    Param(
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, ParameterSetName="FromOrigin")]
        [switch]$Origin,
        [Parameter(Mandatory, ParameterSetName="FromAuth")]
        [switch]$Authentication,
        [Parameter(Mandatory, ParameterSetName="FromModified")]
        [switch]$Modified
    )
    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective -Access Query
    }
    elseif (!$Token.IsPseudoToken) {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        if ($Origin) {
            $Token.Origin | Write-Output
        } elseif ($Authentication) {
            $Token.AuthenticationId
        } elseif ($Modified) {
            $Token.ModifiedId
        } else {
            $Token.Id
        }
    }
}

<#
.SYNOPSIS
Enables virtualization on a Access Token or Process.
.DESCRIPTION
This cmdlet enables virtualization on an Access Token or Process.
.PARAMETER Token
Specify the token to modify.
.PARAMETER Process
Specify the process to modify.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Enable-NtTokenVirtualization
Enable virtualization on the current primary token.
.EXAMPLE
Enable-NtTokenVirtualization -Token $token
Enable virtualization on a specific token.
.EXAMPLE
Enable-NtTokenVirtualization -Process $proc
Enable virtualization on a specific process.
#>
function Enable-NtTokenVirtualization {
    [CmdletBinding(DefaultParameterSetName = "FromProcess")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName="FromToken")]
        [NtCoreLib.NtToken]$Token,
        [parameter(Position = 0, ParameterSetName="FromProcess")]
        [NtCoreLib.NtProcess]$Process
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromProcess" {
            if ($null -EQ $Process) {
                $Process = Get-NtProcess -Current
            }
            $Process.VirtualizationEnabled = $true
        }
        "FromToken" {
            $Token.VirtualizationEnabled = $true
        }
    }
}

<#
.SYNOPSIS
Disables virtualization on a Access Token or Process.
.DESCRIPTION
This cmdlet disables virtualization on an Access Token or Process.
.PARAMETER Token
Specify the token to modify.
.PARAMETER Process
Specify the process to modify.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Disable-NtTokenVirtualization
Disable virtualization on the current primary token.
.EXAMPLE
Disable-NtTokenVirtualization -Token $token
Disable virtualization on a specific token.
.EXAMPLE
Disable-NtTokenVirtualization -Process $proc
Disable virtualization on a specific process.
#>
function Disable-NtTokenVirtualization {
    [CmdletBinding(DefaultParameterSetName = "FromProcess")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName="FromToken")]
        [NtCoreLib.NtToken]$Token,
        [parameter(Position = 0, ParameterSetName="FromProcess")]
        [NtCoreLib.NtProcess]$Process
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromProcess" {
            if ($null -EQ $Process) {
                $Process = Get-NtProcess -Current
            }
            $Process.VirtualizationEnabled = $false
        }
        "FromToken" {
            $Token.VirtualizationEnabled = $false
        }
    }
}

<#
.SYNOPSIS
Check if a token has a specified capability.
.DESCRIPTION
This cmdlet checks if a token has a specified capability. This is primarily for checking AppContainer tokens.
.PARAMETER Token
Specify the token to check. If you do not specify the token then the effective token is used.
.PARAMETER Name
The name of the capability to check.
.INPUTS
None
.OUTPUTS
Boolean
#>
function Test-NtTokenCapability {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position = 0)]
        [string]$Name,
        [NtCoreLib.NtToken]$Token
    )

    if ($null -eq $Token) {
        [NtCoreLib.Security.NtSecurity]::CapabilityCheck($null, $Name)
    } else {
        $Token.CapabilityCheck($Name)
    }
}

<#
.SYNOPSIS
Set the state of a token's privileges.
.DESCRIPTION
This cmdlet will set the state of a token's privileges. This is commonly used to enable debug/backup privileges to perform privileged actions.
If no token is specified then the current effective token is used.
.PARAMETER Privilege
A list of privileges to set their state.
.PARAMETER Token
Optional token object to use to set privileges. Must be accesible for AdjustPrivileges right.
.PARAMETER Attribute
Specify the actual attributes to set. Defaults to Enabled.
.PARAMETER All
Set attributes for all privileges in the token.
.PARAMETER PassThru
Passthrough the updated privilege results.
.PARAMETER Disable
Disable the specified privileges.
.INPUTS
None
.OUTPUTS
List of TokenPrivilege values indicating the new state of all privileges successfully modified.
.EXAMPLE
Set-NtTokenPrivilege SeDebugPrivilege
Enable SeDebugPrivilege on the current effective token
.EXAMPLE
Set-NtTokenPrivilege SeDebugPrivilege -Attributes Disabled
Disable SeDebugPrivilege on the current effective token
.EXAMPLE
Set-NtTokenPrivilege SeBackupPrivilege, SeRestorePrivilege -Token $token
Enable SeBackupPrivilege and SeRestorePrivilege on an explicit token object.
#>
function Set-NtTokenPrivilege {
    [CmdletBinding(DefaultParameterSetName = "FromPrivilege")]
    Param(
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromPrivilege")]
        [alias("Privileges")]
        [NtCoreLib.Security.Token.TokenPrivilegeValue[]]$Privilege,
        [alias("Attributes")]
        [NtCoreLib.PrivilegeAttributes]$Attribute = "Enabled",
        [switch]$Disable,
        [Parameter(Mandatory, ParameterSetName = "FromAllAttributes")]
        [switch]$All,
        [switch]$PassThru
    )

    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective
    }
    else {
        $Token = $Token.Duplicate()
    }

    if ($Disable) {
        $Attribute = "Disabled"
    }

    if ($All) {
        $Privilege = $Token.Privileges.Value
    }

    Use-NtObject($Token) {
        $result = @()
        foreach ($priv in $Privilege) {
            if ($Token.SetPrivilege($priv, $Attribute)) {
                $result += @($Token.GetPrivilege($priv))
            }
            else {
                Write-Warning "Couldn't set privilege $priv"
            }
        }
        if ($PassThru) {
            $result | Write-Output
        }
    }
}

<#
.SYNOPSIS
Enable a token's privileges.
.DESCRIPTION
This cmdlet will enable a token's privileges. This is commonly used to enable debug/backup privileges to perform privileged actions.
If no token is specified then the current effective token is used.
.PARAMETER Privilege
A list of privileges to enable.
.PARAMETER Token
Optional token object to use to enable privileges. Must be accesible for AdjustPrivileges right.
.PARAMETER PassThru
Passthrough the updated privilege results.
.INPUTS
None
.OUTPUTS
List of TokenPrivilege values indicating the new state of all privileges successfully modified.
.EXAMPLE
Enable-NtTokenPrivilege SeDebugPrivilege
Enable SeDebugPrivilege on the current effective token
.EXAMPLE
Enable-NtTokenPrivilege SeBackupPrivilege, SeRestorePrivilege -Token $token
Enable SeBackupPrivilege and SeRestorePrivilege on an explicit token object.
#>
function Enable-NtTokenPrivilege {
    [CmdletBinding(DefaultParameterSetName = "FromPrivilege")]
    Param(
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromPrivilege")]
        [alias("Privileges")]
        [NtCoreLib.Security.Token.TokenPrivilegeValue[]]$Privilege,
        [switch]$PassThru
    )

    Set-NtTokenPrivilege -Token $Token -Privilege $Privilege -PassThru:$PassThru -Attribute Enabled
}

<#
.SYNOPSIS
Disable a token's privileges.
.DESCRIPTION
This cmdlet will disable a token's privileges. If no token is specified then the current effective token is used.
.PARAMETER Privilege
A list of privileges to disable.
.PARAMETER Token
Optional token object to use to disable privileges. Must be accesible for AdjustPrivileges right.
.PARAMETER PassThru
Passthrough the updated privilege results.
.INPUTS
None
.OUTPUTS
List of TokenPrivilege values indicating the new state of all privileges successfully modified.
.EXAMPLE
Disable-NtTokenPrivilege SeDebugPrivilege
Disable SeDebugPrivilege on the current effective token
.EXAMPLE
Disable-NtTokenPrivilege SeBackupPrivilege, SeRestorePrivilege -Token $token
Disable SeBackupPrivilege and SeRestorePrivilege on an explicit token object.
#>
function Disable-NtTokenPrivilege {
    [CmdletBinding(DefaultParameterSetName = "FromPrivilege")]
    Param(
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromPrivilege")]
        [alias("Privileges")]
        [NtCoreLib.Security.Token.TokenPrivilegeValue[]]$Privilege,
        [switch]$PassThru
    )

    Set-NtTokenPrivilege -Token $Token -Privilege $Privilege -PassThru:$PassThru -Attribute Disabled
}

<#
.SYNOPSIS
Get the state of a token's privileges.
.DESCRIPTION
This cmdlet will get the state of a token's privileges.
.PARAMETER Privilege
A list of privileges to get their state.
.PARAMETER Token
Optional token object to use to get privileges. Must be accesible for Query right.
.INPUTS
None
.OUTPUTS
List of TokenPrivilege values indicating the state of all privileges requested.
.EXAMPLE
Get-NtTokenPrivilege
Get all privileges on the current Effective token.
.EXAMPLE
Get-NtTokenPrivilege -Token $token
Get all privileges on an explicit  token.
.EXAMPLE
Get-NtTokenPrivilege -Privilege SeDebugPrivilege
Get state of SeDebugPrivilege on the current process token
.EXAMPLE
Get-NtTokenPrivilege -Privilege SeBackupPrivilege, SeRestorePrivilege -Token $token
Get SeBackupPrivilege and SeRestorePrivilege status on an explicit token object.
#>
function Get-NtTokenPrivilege {
    Param(
        [Parameter(Position = 0, ValueFromPipeline)]
        [NtCoreLib.NtToken]$Token,
        [alias("Privileges")]
        [NtCoreLib.Security.Token.TokenPrivilegeValue[]]$Privilege
    )
    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective -Access Query
    }
    elseif (!$Token.IsPseudoToken) {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        if ($null -ne $Privilege -and $Privilege.Count -gt 0) {
            foreach ($priv in $Privilege) {
                $val = $Token.GetPrivilege($priv)
                if ($null -ne $val) {
                    $val | Write-Output
                }
                else {
                    Write-Warning "Couldn't get privilege $priv"
                }
            }
        }
        else {
            $Token.Privileges | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get a token's groups.
.DESCRIPTION
This cmdlet will get the groups for a token.
.PARAMETER Token
Optional token object to use to get groups. Must be accesible for Query right.
.PARAMETER Restricted
Return the restricted SID list.
.PARAMETER Capabilities
Return the capability SID list.
.PARAMETER Attributes
Specify attributes to filter group list on.
.INPUTS
None
.OUTPUTS
List of UserGroup values indicating the state of all groups.
.EXAMPLE
Get-NtTokenGroup
Get all groups on the effective process token
.EXAMPLE
Get-NtTokenGroup -Token $token
Get groups on an explicit token object.
.EXAMPLE
Get-NtTokenGroup -Attributes Enabled
Get groups that are enabled.
#>
function Get-NtTokenGroup {
    [CmdletBinding(DefaultParameterSetName = "Normal")]
    Param(
        [Parameter(Position = 0, ValueFromPipeline)]
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, ParameterSetName = "Restricted")]
        [switch]$Restricted,
        [Parameter(Mandatory, ParameterSetName = "Capabilities")]
        [switch]$Capabilities,
        [Parameter(Mandatory, ParameterSetName = "Device")]
        [switch]$Device,
        [NtCoreLib.GroupAttributes]$Attributes = 0
    )
    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective -Access Query
    }
    elseif (!$Token.IsPseudoToken) {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        $groups = if ($Restricted) {
            $Token.RestrictedSids
        }
        elseif ($Capabilities) {
            $Token.Capabilities
        }
        elseif ($Device) {
            $Token.DeviceGroups
        }
        else {
            $Token.Groups
        }

        if ($Attributes -ne 0) {
            $groups = $groups | Where-Object { ($_.Attributes -band $Attributes) -eq $Attributes }
        }

        $groups | Write-Output
    }
}

<#
.SYNOPSIS
Sets a token's group state.
.DESCRIPTION
This cmdlet will sets the state of groups for a token.
.PARAMETER Token
Optional token object to use to set groups. Must be accesible for AdjustGroups right.
.PARAMETER Sid
Specify the list of SIDs to set.
.PARAMETER Attributes
Specify the attributes to set on the SIDs.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-NtTokenGroup -Sid "WD" -Attributes 0
Set the Everyone SID to disabled.
.EXAMPLE
Set-NtTokenGroup -Sid "WD" -Attributes Enabled
Set the Everyone SID to enabled.
#>
function Set-NtTokenGroup {
    [CmdletBinding()]
    Param(
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Security.Authorization.Sid[]]$Sid,
        [Parameter(Mandatory, Position = 1)]
        [NtCoreLib.GroupAttributes]$Attributes
    )
    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective -Access AdjustGroups
    }
    else {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        $Token.SetGroups($Sid, $Attributes)
    }
}

<#
.SYNOPSIS
Resets a token's group state.
.DESCRIPTION
This cmdlet will resets the state of groups for a token.
.PARAMETER Token
Optional token object to use to reset groups. Must be accesible for AdjustGroups right.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Reset-NtTokenGroup
Reset the groups for the current token.
.EXAMPLE
Reset-NtTokenGroup -Token $token
Reset the groups for the a specified token.
#>
function Reset-NtTokenGroup {
    [CmdletBinding()]
    Param(
        [NtCoreLib.NtToken]$Token
    )
    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective -Access AdjustGroups
    }
    else {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        $Token.ResetGroups()
    }
}

<#
.SYNOPSIS
Enable a token's group.
.DESCRIPTION
This cmdlet will enable one or more groups on a token. They can't be marked as mandatory.
.PARAMETER Token
Optional token object to use to enable groups. Must be accesible for AdjustGroups right.
.PARAMETER Sid
Specify the list of group SIDs to enable.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Enable-NtTokenGroup -Sid "WD"
Enable the Everyone SID for the current token.
.EXAMPLE
Enable-NtTokenGroup -Sid "WD" -Token $token
Enable the Everyone SID on a specified token.
#>
function Enable-NtTokenGroup {
    [CmdletBinding()]
    Param(
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Security.Authorization.Sid[]]$Sid
    )

    Set-NtTokenGroup -Token $Token -Sid $Sid -Attributes Enabled
}

<#
.SYNOPSIS
Disable a token's group.
.DESCRIPTION
This cmdlet will disable one or more groups on a token. They can't be marked as mandatory.
.PARAMETER Token
Optional token object to use to disable groups. Must be accesible for AdjustGroups right.
.PARAMETER Sid
Specify the list of group SIDs to disable.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Disable-NtTokenGroup -Sid "WD"
Disable the Everyone SID for the current token.
.EXAMPLE
Disable-NtTokenGroup -Sid "WD" -Token $token
Disable the Everyone SID on a specified token.
#>
function Disable-NtTokenGroup {
    [CmdletBinding()]
    Param(
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Security.Authorization.Sid[]]$Sid
    )

    Set-NtTokenGroup -Token $Token -Sid $Sid -Attributes Enabled
}

<#
.SYNOPSIS
Get a token's user SID or one of the other single SID values.
.DESCRIPTION
This cmdlet will get user SID for a token. Or one of the other SIDs such as Owner.
.PARAMETER Owner
Specify to get the owner.
.PARAMETER Group
Specify to get the default group.
.PARAMETER Integrity
Specify to get the integrity level.
.PARAMETER TrustLevel
Specify to get the process trust level.
.PARAMETER LogonId
Specify to get the logon SID.
.PARAMETER Package
Specify to get the AppContainer package SID.
.PARAMETER Token
Optional token object to use to get SID. Must be accesible for Query right.
.PARAMETER AsSddl
Specify to convert the SID to SDDL.
.PARAMETER AsName
Specify to convert the SID to a name.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.Sid
.EXAMPLE
Get-NtTokenSid
Get user SID on the current effective token
.EXAMPLE
Get-NtTokenSid -Token $token
Get user SID on an explicit token object.
.EXAMPLE
Get-NtTokenSid -Group
Get the default group SID.
.EXAMPLE
Get-NtTokenSid -Owner
Get the default owner SID.
#>
function Get-NtTokenSid {
    [CmdletBinding(DefaultParameterSetName = "User")]
    Param(
        [Parameter(Position = 0, ValueFromPipeline)]
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, ParameterSetName = "Owner")]
        [switch]$Owner,
        [Parameter(Mandatory, ParameterSetName = "Group")]
        [switch]$Group,
        [Parameter(Mandatory, ParameterSetName = "TrustLevel")]
        [switch]$TrustLevel,
        [Parameter(Mandatory, ParameterSetName = "Login")]
        [switch]$LogonId,
        [Parameter(Mandatory, ParameterSetName = "Integrity")]
        [switch]$Integrity,
        [Parameter(Mandatory, ParameterSetName = "Package")]
        [switch]$Package,
        [alias("ToSddl")]
        [switch]$AsSddl,
        [alias("ToName")]
        [switch]$AsName
    )
    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective -Access Query
    }
    elseif (!$Token.IsPseudoToken) {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        $sid = switch ($PsCmdlet.ParameterSetName) {
            "User" { $Token.User.Sid }
            "Owner" { $Token.Owner }
            "Group" { $Token.PrimaryGroup }
            "TrustLevel" { $Token.TrustLevel }
            "Login" { $Token.LogonSid.Sid }
            "Integrity" { $Token.IntegrityLevelSid.Sid }
            "Package" { $Token.AppContainerSid }
        }

        if ($AsSddl) {
            $sid.ToString() | Write-Output
        }
        elseif ($AsName) {
            $sid.Name | Write-Output
        }
        else {
            $sid | Write-Output
        }
    }
}

<#
.SYNOPSIS
Set a token SID.
.DESCRIPTION
This cmdlet will set a SID on the token such as default owner or group.
.PARAMETER Owner
Specify to set the default owner.
.PARAMETER Group
Specify to set the default group.
.PARAMETER Integrity
Specify to set the integrity level.
.PARAMETER Token
Optional token object to use to set group. Must be accesible for AdjustDefault right.
.PARAMETER Sid
Specify the SID to set.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-NtTokenSid -Owner -Sid "S-1-2-3-4"
Set default owner on the current effective token
.EXAMPLE
Set-NtTokenOwner -Owner -Token $token -Sid "S-1-2-3-4"
Set default owner on an explicit token object.
.EXAMPLE
Set-NtTokenOwner -Group -Sid "S-1-2-3-4"
Set the default group.
#>
function Set-NtTokenSid {
    [CmdletBinding(DefaultParameterSetName = "Normal")]
    Param(
        [Parameter(Position = 1)]
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [Parameter(Mandatory, ParameterSetName = "Owner")]
        [switch]$Owner,
        [Parameter(Mandatory, ParameterSetName = "Group")]
        [switch]$Group,
        [Parameter(Mandatory, ParameterSetName = "Integrity")]
        [switch]$Integrity
    )
    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective -Access AdjustDefault
    }
    else {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        switch ($PsCmdlet.ParameterSetName) {
            "Owner" { $Token.Owner = $Sid }
            "Group" { $Token.PrimaryGroup = $Sid }
            "Integrity" { $Token.IntegrityLevelSid = $sid }
        } }
}

<#
.SYNOPSIS
Get a token's default owner or group.
.DESCRIPTION
This cmdlet will get the default owner or group for a token.
.PARAMETER Group
Specify to get the default group rather than default owner.
.PARAMETER Token
Optional token object to use to get group. Must be accesible for Query right.
.INPUTS
None
.OUTPUTS
UserGroup for the owner.
.EXAMPLE
Get-NtTokenOwner
Get default owner on the current effective token
.EXAMPLE
Get-NtTokenOwner -Token $token
Get default owner on an explicit token object.
.EXAMPLE
Get-NtTokenOwner -Group
Get the default group.
#>
function Get-NtTokenOwner {
    [CmdletBinding()]
    Param(
        [NtCoreLib.NtToken]$Token,
        [switch]$Group
    )
    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective -Access Query
    }
    elseif (!$Token.IsPseudoToken) {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        if ($Group) {
            $Token.PrimaryGroup | Write-Output
        }
        else {
            $Token.Owner | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get a token's mandatory policy.
.DESCRIPTION
This cmdlet will get the token's mandatory policy.
.PARAMETER Group
Specify to get the default group rather than default owner.
.PARAMETER Token
Optional token object to use to get group. Must be accesible for Query right.
.INPUTS
None
.OUTPUTS
The Token Mandatory Policy
.EXAMPLE
Get-NtTokenMandatoryPolicy
Get the mandatory policy for the current effective token.
.EXAMPLE
Get-NtTokenMandatoryPolicy -Token $token
Get default owner on an explicit token object.
#>
function Get-NtTokenMandatoryPolicy {
    [CmdletBinding()]
    Param(
        [NtCoreLib.NtToken]$Token
    )
    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective -Access Query
    }
    elseif (!$Token.IsPseudoToken) {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        $Token.MandatoryPolicy
    }
}

<#
.SYNOPSIS
Remove privileges from a token.
.DESCRIPTION
This cmdlet will remove privileges from a token. Note that this completely removes the privilege, not just disable.
.PARAMETER Privileges
A list of privileges to remove.
.PARAMETER Token
Optional token object to use to remove privileges.
.INPUTS
None
.OUTPUTS
List of TokenPrivilege values indicating the new state of all privileges successfully modified.
.EXAMPLE
Remove-NtTokenPrivilege SeDebugPrivilege
Remove SeDebugPrivilege from the current effective token
.EXAMPLE
Remove-NtTokenPrivilege SeBackupPrivilege, SeRestorePrivilege -Token $token
Remove SeBackupPrivilege and SeRestorePrivilege from an explicit token object.
#>
function Remove-NtTokenPrivilege {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [alias("Privileges")]
        [NtCoreLib.Security.Token.TokenPrivilegeValue[]]$Privilege,
        [NtCoreLib.NtToken]$Token
    )
    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective
    }
    else {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        $result = @()
        foreach ($priv in $Privilege) {
            if (!$Token.RemovePrivilege($priv)) {
                Write-Warning "Can't remove $priv from token."
            }
        }
        return $result
    }
}

<#
.SYNOPSIS
Set the integrity level of a token.
.DESCRIPTION
This cmdlet will set the integrity level of a token. If you want to raise the level you must have SeTcbPrivilege otherwise you can only lower it.
If no token is specified then the current process token is used.
.PARAMETER IntegrityLevel
Specify the integrity level.
.PARAMETER Token
Optional token object to use to set privileges. Must be accesible for AdjustDefault right.
.PARAMETER Adjustment
Increment or decrement the IL level from the base specified in -IntegrityLevel.
.PARAMETER IntegrityLevelRaw
Specify the integrity level as a raw value.
.INPUTS
None
.EXAMPLE
Set-NtTokenIntegrityLevel Low
Set the current token's integrity level to low.
.EXAMPLE
Set-NtTokenIntegrityLevel Low -Token $Token
Set a specific token's integrity level to low.
.EXAMPLE
Set-NtTokenIntegrityLevel Low -Adjustment -16
Set the current token's integrity level to low minus 16.
.EXAMPLE
Set-NtTokenIntegrityLevel -IntegrityLevelRaw 0x800
Set the current token's integrity level to 0x800.
#>
function Set-NtTokenIntegrityLevel {
    [CmdletBinding(DefaultParameterSetName = "FromIL")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromIL")]
        [NtCoreLib.TokenIntegrityLevel]$IntegrityLevel,
        [NtCoreLib.NtToken]$Token,
        [Parameter(ParameterSetName = "FromIL")]
        [Int32]$Adjustment = 0,
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromRaw")]
        [Int32]$IntegrityLevelRaw
    )
    switch ($PSCmdlet.ParameterSetName) {
        "FromIL" {
            $il_raw = $IntegrityLevel.ToInt32($null) + $Adjustment
        }
        "FromRaw" {
            $il_raw = $IntegrityLevelRaw
        }
    }

    if ($Token -eq $null) {
        $Token = Get-NtToken -Effective
    }
    else {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        $Token.SetIntegrityLevelRaw($il_raw) | Out-Null
    }
}

<#
.SYNOPSIS
Get the integrity level of a token.
.DESCRIPTION
This cmdlet will gets the integrity level of a token.
.PARAMETER Token
Optional token object to use to get integrity level. Must be accesible for Query right.
.INPUTS
None
.OUTPUTS
NtCoreLib.TokenIntegrityLevel
.EXAMPLE
Get-NtTokenIntegrityLevel
Get the current token's integrity level.
.EXAMPLE
Get-NtTokenIntegrityLevel -Token $Token
Get a specific token's integrity level.
#>
function Get-NtTokenIntegrityLevel {
    [CmdletBinding(DefaultParameterSetName = "FromIL")]
    Param(
        [Parameter(Position = 0)]
        [NtCoreLib.NtToken]$Token
    )

    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective
    }
    else {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        $Token.IntegrityLevel | Write-Output
    }
}

<#
.SYNOPSIS
Opens an impersonation token from a process or thread using NtImpersonateThread
.DESCRIPTION
This cmdlet opens an impersonation token from a process using NtImpersonateThread. While SeDebugPrivilege
allows you to bypass the security of processes and threads it doesn't mean you can open the primary token.
This cmdlet allows you to get past that by getting a handle to the first thread and then impersonating it,
as long as the thread isn't impersonating something else you'll get back a copy of the primary token.
.PARAMETER ProcessId
A process to open to get the token from.
.PARAMETER ThreadId
A thread to open to get the token from.
.PARAMETER Access
Access rights for the opened token.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtToken
.EXAMPLE
Get-NtTokenFromProcess -ProcessId 1234
Gets token from process ID 1234.
.EXAMPLE
Get-NtTokenFromProcess -ProcessId 1234 -Access Query
Gets token from process ID 1234 with only Query access.
.EXAMPLE
Get-NtTokenFromProcess -ThreadId 1234
Gets token from process ID 1234.
#>
function Get-NtTokenFromProcess {
    [CmdletBinding(DefaultParameterSetName = "FromProcess")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromProcess", Mandatory = $true)]
        [ValidateScript( { $_ -ge 0 })]
        [int]$ProcessId,
        [Parameter(ParameterSetName = "FromThread", Mandatory = $true)]
        [ValidateScript( { $_ -ge 0 })]
        [int]$ThreadId,
        [NtCoreLib.TokenAccessRights]$Access = "MaximumAllowed"
    )

    Set-NtTokenPrivilege SeDebugPrivilege
    $t = $null

    try {
        if ($PsCmdlet.ParameterSetName -eq "FromProcess") {
            $t = Use-NtObject($p = Get-NtProcess -ProcessId $ProcessId) {
                $p.GetFirstThread("DirectImpersonation")
            }
        }
        else {
            $t = Get-NtThread -ThreadId $ThreadId -Access DirectImpersonation
        }

        $current = Get-NtThread -Current -PseudoHandle
        Use-NtObject($t, $current.ImpersonateThread($t)) {
            Get-NtToken -Impersonation -Thread $current -Access $Access
        }
    }
    catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Prints the details of a token.
.DESCRIPTION
This cmdlet opens prints basic details about it a token.
.PARAMETER Token
Specify the token to format.
.PARAMETER All
Show all information.
.PARAMETER User
Show user information.
.PARAMETER Group
Show group information. Also prints capability sids and restricted sids if a sandboxed token.
.PARAMETER Privilege
Show privilege information.
.PARAMETER Integrity
Show integrity information.
.PARAMETER SecurityAttributes
Show token security attributes.
.PARAMETER UserClaims
Show token user claim attributes.
.PARAMETER DeviceClaims
Show token device claim attributes.
.PARAMETER TrustLevel
Show token trust level.
.PARAMETER Information
Show token information such as type, impersonation level and ID.
.PARAMETER Owner
Show token owner.
.PARAMETER PrimaryGroup
Show token primary group.
.PARAMETER DefaultDacl
Show token default DACL.
.PARAMETER FullDefaultDacl
Show the default DACL in full rather than a summary.
.PARAMETER Basic
Show basic token information, User, Group, Privilege and Integrity.
.PARAMETER MandatoryPolicy
Show mandatory integrity policy.
.OUTPUTS
System.String
.EXAMPLE
Format-NtToken -Token $token
Print the user name of the token.
.EXAMPLE
Format-NtToken -Token $token -Basic
Print basic details for the token.
.EXAMPLE
Format-NtToken -Token $token -All
Print all details for the token.
.EXAMPLE
Format-NtToken -Token $token -User -Group
Print the user and groups of the token.
.EXAMPLE
Format-NtToken -Token $token -DefaultDacl
Print the default DACL of the token.
.EXAMPLE
Format-NtToken -Token $token -FullDefaultDacl
Print the default DACL of the token in full.
#>
function Format-NtToken {
    [CmdletBinding(DefaultParameterSetName = "UserOnly")]
    Param(
        [parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [NtCoreLib.NtToken]$Token,
        [parameter(ParameterSetName = "Complex")]
        [switch]$All,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Basic,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Group,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Privilege,
        [parameter(ParameterSetName = "Complex")]
        [switch]$User,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Integrity,
        [parameter(ParameterSetName = "Complex")]
        [switch]$SecurityAttributes,
        [parameter(ParameterSetName = "Complex")]
        [switch]$UserClaims,
        [parameter(ParameterSetName = "Complex")]
        [switch]$DeviceClaims,
        [parameter(ParameterSetName = "Complex")]
        [switch]$DeviceGroup,
        [parameter(ParameterSetName = "Complex")]
        [switch]$TrustLevel,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Information,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Owner,
        [parameter(ParameterSetName = "Complex")]
        [switch]$PrimaryGroup,
        [parameter(ParameterSetName = "Complex")]
        [switch]$DefaultDacl,
        [parameter(ParameterSetName = "Complex")]
        [switch]$FullDefaultDacl,
        [parameter(ParameterSetName = "Complex")]
        [switch]$MandatoryPolicy
    )

    if ($All) {
        $Group = $true
        $User = $true
        $Privilege = $true
        $Integrity = $true
        $SecurityAttributes = $true
        $DeviceClaims = $true
        $UserClaims = $true
        $TrustLevel = $true
        $Information = $true
        $Owner = $true
        $PrimaryGroup = $true
        $DefaultDacl = $true
        $DeviceGroup = $true
        $MandatoryPolicy = $true
    }
    elseif ($Basic) {
        $Group = $true
        $User = $true
        $Privilege = $true
        $Integrity = $true
    }

    if ($PSCmdlet.ParameterSetName -eq "UserOnly") {
        $token.User.ToString()
        return
    }

    if ($User) {
        "USER INFORMATION"
        "----------------"
        Format-ObjectTable $token.User.Sid | Write-Output
    }

    if ($Owner) {
        "OWNER INFORMATION"
        "---------------- "
        Format-ObjectTable $token.Owner | Write-Output
    }

    if ($PrimaryGroup) {
        "PRIMARY GROUP INFORMATION"
        "-------------------------"
        Format-ObjectTable $token.PrimaryGroup | Write-Output
    }

    if ($Group) {
        if ($Token.GroupCount -gt 0) {
            "GROUP SID INFORMATION"
            "-----------------"
            Format-ObjectTable $token.Groups | Write-Output
        }

        if ($token.AppContainer -and $token.Capabilities.Length -gt 0) {
            "APPCONTAINER INFORMATION"
            "------------------------"
            Format-ObjectTable $token.AppContainerSid | Write-Output
            "CAPABILITY SID INFORMATION"
            "----------------------"
            Format-ObjectTable $token.Capabilities | Write-Output
        }

        if ($token.Restricted -and $token.RestrictedSids.Length -gt 0) {
            if ($token.WriteRestricted) {
                "WRITE RESTRICTED SID INFORMATION"
                "--------------------------------"
            }
            else {
                "RESTRICTED SID INFORMATION"
                "--------------------------"
            }
            Format-ObjectTable $token.RestrictedSids | Write-Output
        }
    }

    if ($Privilege -and $Token.Privileges.Length -gt 0) {
        "PRIVILEGE INFORMATION"
        "---------------------"
        Format-ObjectTable $token.Privileges | Write-Output
    }

    if ($Integrity) {
        "INTEGRITY LEVEL"
        "---------------"
        Format-ObjectTable $token.IntegrityLevel | Write-Output
    }

    if ($MandatoryPolicy) {
        "MANDATORY POLICY"
        "----------------"
        Format-ObjectTable $token.MandatoryPolicy | Write-Output
    }

    if ($TrustLevel) {
        $trust_level = $token.TrustLevel
        if ($trust_level -ne $null) {
            "TRUST LEVEL"
            "-----------"
            Format-ObjectTable $trust_level | Write-Output
        }
    }

    if ($SecurityAttributes -and $Token.SecurityAttributes.Length -gt 0) {
        "SECURITY ATTRIBUTES"
        "-------------------"
        Format-ObjectTable $token.SecurityAttributes | Write-Output
    }

    if ($UserClaims -and $Token.UserClaimAttributes.Length -gt 0) {
        "USER CLAIM ATTRIBUTES"
        "-------------------"
        Format-ObjectTable $token.UserClaimAttributes | Write-Output
    }

    if ($DeviceClaims -and $Token.DeviceClaimAttributes.Length -gt 0) {
        "DEVICE CLAIM ATTRIBUTES"
        "-------------------"
        Format-ObjectTable $token.DeviceClaimAttributes | Write-Output
    }

    if ($DeviceGroup -and $Token.DeviceGroups.Length -gt 0) {
        "DEVICE GROUP SID INFORMATION"
        "----------------------------"
        Format-ObjectTable $token.DeviceGroups | Write-Output
    }

    if (($DefaultDacl -or $FullDefaultDacl) -and ($null -ne $Token.DefaultDacl)) {
        $summary = !$FullDefaultDacl
        "DEFAULT DACL"
        Format-NtAcl -Acl $Token.DefaultDacl -Type "Directory" -Name "------------" -Summary:$summary | Write-Output
        if ($summary) {
            Write-Output ""
        }
    }

    if ($Information) {
        "TOKEN INFORMATION"
        "-----------------"
        "Type          : {0}" -f $token.TokenType
        if ($token.TokenType -eq "Impersonation") {
            "Imp Level     : {0}" -f $token.ImpersonationLevel
        }
        "ID            : {0}" -f $token.Id
        "Auth ID       : {0}" -f $token.AuthenticationId
        "Origin ID     : {0}" -f $token.Origin
        "Modified ID   : {0}" -f $token.ModifiedId
        "Session ID    : {0}" -f $token.SessionId
        "Elevated      : {0}" -f $token.Elevated
        "Elevation Type: {0}" -f $token.ElevationType
        "Flags         : {0}" -f $token.Flags
    }
}

<#
.SYNOPSIS
Prints the details of the current token.
.DESCRIPTION
This cmdlet opens the current token and prints basic details about it. This is similar to the Windows whoami
command but runs in process and will print information about the current thread token if you're impersonating.
.PARAMETER All
Show all information.
.PARAMETER User
Show user information.
.PARAMETER Group
Show group information. Also prints capability sids and restricted sids if a sandboxed token.
.PARAMETER Privilege
Show privilege information.
.PARAMETER Integrity
Show integrity information.
.PARAMETER SecurityAttributes
Show token security attributes.
.PARAMETER UserClaims
Show token user claim attributes.
.PARAMETER DeviceClaims
Show token device claim attributes.
.PARAMETER TrustLevel
Show token trust level.
.PARAMETER Information
Show token information such as type, impersonation level and ID.
.PARAMETER Owner
Show token owner.
.PARAMETER PrimaryGroup
Show token primary group.
.PARAMETER DefaultDacl
Show token default DACL.
.PARAMETER FullDefaultDacl
Show the default DACL in full rather than a summary.
.PARAMETER Basic
Show basic token information, User, Group, Privilege and Integrity.
.PARAMETER MandatoryPolicy
Show mandatory integrity policy.
.PARAMETER Thread
Specify a thread to use when capturing the effective token.
.OUTPUTS
Text data
.EXAMPLE
Show-NtTokenEffective
Show only the user name of the current token.
.EXAMPLE
Show-NtTokenEffective -All
Show all details for the current token.
.EXAMPLE
Show-NtTokenEffective -Basic
Show basic details for the current token.
.EXAMPLE
Show-NtTokenEffective -User -Group
Show the user and groups of the current token.
#>
function Show-NtTokenEffective {
    [CmdletBinding(DefaultParameterSetName = "UserOnly")]
    Param(
        [parameter(ParameterSetName = "Complex")]
        [switch]$All,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Basic,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Group,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Privilege,
        [parameter(ParameterSetName = "Complex")]
        [switch]$User,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Integrity,
        [parameter(ParameterSetName = "Complex")]
        [switch]$SecurityAttributes,
        [parameter(ParameterSetName = "Complex")]
        [switch]$UserClaims,
        [parameter(ParameterSetName = "Complex")]
        [switch]$DeviceClaims,
        [parameter(ParameterSetName = "Complex")]
        [switch]$TrustLevel,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Information,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Owner,
        [parameter(ParameterSetName = "Complex")]
        [switch]$PrimaryGroup,
        [parameter(ParameterSetName = "Complex")]
        [switch]$DefaultDacl,
        [parameter(ParameterSetName = "Complex")]
        [switch]$FullDefaultDacl,
        [parameter(ParameterSetName = "Complex")]
        [switch]$MandatoryPolicy,
        [NtCoreLib.NtThread]$Thread
    )

    Use-NtObject($token = Get-NtToken -Effective -Thread $Thread) {
        if ($PsCmdlet.ParameterSetName -eq "UserOnly") {
            Format-NtToken -Token $token
        }
        else {
            $args = @{
                All                = $All
                Basic              = $Basic
                Group              = $Group
                Privilege          = $Privilege
                User               = $User
                Integrity          = $Integrity
                SecurityAttributes = $SecurityAttributes
                UserClaims         = $UserClaims
                DeviceClaims       = $DeviceClaims
                TrustLevel         = $TrustLevel
                Information        = $Information
                Owner              = $Owner
                PrimaryGroup       = $PrimaryGroup
                Token              = $token
                DefaultDacl        = $DefaultDacl
                FullDefaultDacl    = $FullDefaultDacl
                MandatoryPolicy    = $MandatoryPolicy
            }
            Format-NtToken @args
        }
    }
}

function Start-NtTokenViewer {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [NtCoreLib.NtObject]$Handle,
        [string]$Text
    )

    Use-NtObject($dup_handle = $Handle.Duplicate()) {
        $cmdline = "TokenViewer --handle={0}" -f $dup_handle.Handle.DangerousGetHandle()
        if ($Text -ne "") {
            $cmdline += " ""--text=$Text"""
        }
        [NtObjectManager.Utils.PSUtils]::StartUtilityProcess("$PSScriptRoot\TokenViewer.exe", $cmdline, $false, $dup_handle)
    }
}

<#
.SYNOPSIS
Display a UI viewer for a NT token.
.DESCRIPTION
This function will create an instance of the TokenViewer application to display the opened token.
.PARAMETER Token
The token to view.
.PARAMETER Text
Additional text to show in title bar for this token.
.PARAMETER Process
The process to display the token for.
.PARAMETER ProcessId
A process ID of a process to display the token for.
.PARAMETER Name
The name of a process to display the token for.
.PARAMETER MaxTokens
When getting the name/command line only display at most this number of tokens.
.PARAMETER All
Show dialog with all access tokens.
.PARAMETER RunAsAdmin
Specify to elevate the process to admin.
.PARAMETER ServiceName
Specify the name of a service to display the token for.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Show-NtToken
Display the primary token for the current process.
.EXAMPLE
Show-NtToken -ProcessId 1234
Display the primary token for the process with PID 1234.
.EXAMPLE
Show-NtToken -Process $process
Display the primary token for the process specified with an NtProcess object.
.EXAMPLE
$ps | Select-Object -First 5 | Show-NtToken
Display the first 5 primary tokens from a list of processes.
.EXAMPLE
Show-NtToken -Token $token
Display the token specified with an NtToken object.
.EXAMPLE
Show-NtToken -Name "notepad.exe"
Display the primary tokens from accessible processes named notepad.exe.
.EXAMPLE
Show-NtToken -Name "notepad.exe" -MaxTokens 5
Display up to 5 primary tokens from accessible processes named notepad.exe.
.EXAMPLE
Show-NtToken -All
Show a list of all accessible tokens to choose from.
.EXAMPLE
Show-NtToken -All -RunAsAdmin
Show a list of all accessible tokens to choose from and run as an administrator.
.EXAMPLE
Show-NtToken -ServiceName "AppInfo"
Display the primary token for the AppInfo service.
#>
function Show-NtToken {
    [CmdletBinding(DefaultParameterSetName = "FromPid")]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromToken", ValueFromPipeline)]
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromProcess", ValueFromPipeline)]
        [NtCoreLib.NtProcess]$Process,
        [Parameter(Position = 0, ParameterSetName = "FromPid")]
        [int]$ProcessId = $pid,
        [Parameter(Mandatory, ParameterSetName = "FromName")]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName = "FromCommandLine")]
        [string]$CommandLine,
        [Parameter(ParameterSetName = "FromName")]
        [Parameter(ParameterSetName = "FromCommandLine")]
        [int]$MaxTokens = 0,
        [Parameter(Mandatory, ParameterSetName = "FromServiceName")]
        [string]$ServiceName,
        [Parameter(ParameterSetName = "All")]
        [switch]$All,
        [Parameter(ParameterSetName = "All")]
        [Parameter(ParameterSetName = "FromPid")]
        [Parameter(ParameterSetName = "FromServiceName")]
        [switch]$RunAsAdmin
    )

    PROCESS {
        if (-not $(Test-Path "$PSScriptRoot\TokenViewer.exe" -PathType Leaf)) {
            Write-Error "Missing token viewer application $PSScriptRoot\TokenViewer.exe"
            return
        }

        switch ($PSCmdlet.ParameterSetName) {
            "FromProcess" {
                $text = "$($Process.Name):$($Process.ProcessId)"
                Start-NtTokenViewer $Process -Text $text
            }
            "FromName" {
                Use-NtObject($ps = Get-NtProcess -Name $Name -Access QueryLimitedInformation) {
                    $result = $ps
                    if ($MaxTokens -gt 0) {
                        $result = $ps | Select-Object -First $MaxTokens
                    }
                    $result | Show-NtToken
                }
            }
            "FromCommandLine" {
                Use-NtObject($ps = Get-NtProcess -CommandLine $CommandLine -Access QueryLimitedInformation) {
                    $result = $ps
                    if ($MaxTokens -gt 0) {
                        $result = $ps | Select-Object -First $MaxTokens
                    }
                    $result | Show-NtToken
                }
            }
            "FromPid" {
                [NtObjectManager.Utils.PSUtils]::StartAdminProcess("$PSScriptRoot\TokenViewer.exe", "--pid=$ProcessId", $false, $RunAsAdmin)
            }
            "FromServiceName" {
                [NtObjectManager.Utils.PSUtils]::StartAdminProcess("$PSScriptRoot\TokenViewer.exe", "`"--service=$ServiceName`"", $false, $RunAsAdmin)
            }
            "FromToken" {
                Start-NtTokenViewer $Token
            }
            "All" {
                [NtObjectManager.Utils.PSUtils]::StartAdminProcess("$PSScriptRoot\TokenViewer.exe", "", $false, $RunAsAdmin)
            }
        }
    }
}

<#
.SYNOPSIS
Allocates a new block of virtual memory.
.DESCRIPTION
This cmdlet allocates a new block of virtual memory in a specified process with specified set of protection. Returns the address.
.PARAMETER Size
The size of the allocated memory region.
.PARAMETER BaseAddress
Optional address to allocate the memory at. Can be 0 which requests the kernel to pick an address.
.PARAMETER Process
The process to allocate the memory in, defaults to current process.
.PARAMETER AllocationType
The type of allocation to make. Defaults to Reserve and Commit.
.PARAMETER Protection
The protection for the memory region. Defaults to ReadWrite.
.PARAMETER AsBuffer
Specify to return as a safe buffer in the current virtual address space.
.OUTPUTS
int64
NtCoreLib.Native.SafeBuffers.SafeVirtualMemoryBuffer
.EXAMPLE
$addr = Add-NtVirtualMemory 0x10000
Allocate a block 0x10000 in size.
.EXAMPLE
$addr = Add-NtVirtualMemory 0x10000 -Process $process
Allocate a block 0x10000 in size in the specified process.
.EXAMPLE
$addr = Add-NtVirtualMemory 0x10000 -AllocationType Reserve
Reserve a block 0x10000 in size but don't yet commit it.
.EXAMPLE
$addr = Add-NtVirtualMemory 0x10000 -Protection ExecuteReadWrite
Allocate a block 0x10000 in size with Read, Write and Execution protection.
#>
function Add-NtVirtualMemory {
    [CmdletBinding(DefaultParameterSetName="FromProcess")]
    param (
        [parameter(Mandatory, Position = 0)]
        [int64]$Size,
        [int64]$BaseAddress,
        [parameter(ParameterSetName="FromProcess")]
        [NtCoreLib.NtProcess]$Process = [NtCoreLib.NtProcess]::Current,
        [NtCoreLib.MemoryAllocationType]$AllocationType = "Reserve, Commit",
        [NtCoreLib.MemoryAllocationProtect]$Protection = "ReadWrite",
        [parameter(Mandatory, ParameterSetName="AsBuffer")]
        [switch]$AsBuffer
    )
    if ($AsBuffer) {
        [NtCoreLib.Native.SafeBuffers.SafeVirtualMemoryBuffer]::new($BaseAddress, $Size, $AllocationType, $Protection)
    } else {
        $Process.AllocateMemory($BaseAddress, $Size, $AllocationType, $Protection)
    }
}

<#
.SYNOPSIS
Deallocates a block of virtual memory.
.DESCRIPTION
This cmdlet deallocates a block of virtual memory in a specified process.
.PARAMETER Size
The size of the region to  decommit. Only valid when FreeType is Decommit.
.PARAMETER Address
The address to deallocate the memory at.
.PARAMETER Process
The process to deallocate the memory in, defaults to current process.
.PARAMETER MemoryType
The type of allocation operation to perform. Release frees the memory while
Decommit makes it inaccessible.
.OUTPUTS
None
.EXAMPLE
Remove-NtVirtualMemory $addr
Free block at $addr
.EXAMPLE
Remove-NtVirtualMemory $addr -Process $process
Free a block in the specified process.
.EXAMPLE
Remove-NtVirtualMemory $addr -Size 0x1000 -FreeType Decommit
Decommit a 4096 byte block at $addr
#>
function Remove-NtVirtualMemory {
    param (
        [parameter(Mandatory, Position = 0)]
        [int64]$Address,
        [int64]$Size,
        [NtCoreLib.MemoryFreeType]$FreeType = "Release",
        [NtCoreLib.NtProcess]$Process = [NtCoreLib.NtProcess]::Current
    )
    $Process.FreeMemory($Address, $Size, $FreeType)
}

<#
.SYNOPSIS
Get information about a virtual memory region by address or for the entire process.
.DESCRIPTION
This cmdlet gets information about a virtual memory region or all regions in a process.
.PARAMETER Address
The address to get information about.
.PARAMETER Process
The process to query for memory information, defaults to current process.
.PARAMETER All
Show all memory regions.
.PARAMETER Name
Show only memory regions for the named mapped file.
.PARAMETER IncludeFree
When showing all memory regions specify to include free regions as well.
.OUTPUTS
NtCoreLib.MemoryInformation
.EXAMPLE
Get-NtVirtualMemory $addr
Get the memory information for the specified address for the current process.
.EXAMPLE
Get-NtVirtualMemory $addr -Process $process
Get the memory information for the specified address in another process.
.EXAMPLE
Get-NtVirtualMemory
Get all memory information for the current process.
.EXAMPLE
Get-NtVirtualMemory -Process $process
Get all memory information in another process.
.EXAMPLE
Get-NtVirtualMemory -Process $process -IncludeFree
Get all memory information in another process including free regions.
.EXAMPLE
Get-NtVirtualMemory -Type Mapped
Get all mapped memory information for the current process.
.EXAMPLE
Get-NtVirtualMemory -Name file.exe
Get all mapped memory information where the mapped name is file.exe.
#>
function Get-NtVirtualMemory {
    [CmdletBinding(DefaultParameterSetName = "All")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromAddress")]
        [int64]$Address,
        [NtCoreLib.NtProcess]$Process = [NtCoreLib.NtProcess]::Current,
        [parameter(ParameterSetName = "All")]
        [switch]$All,
        [parameter(ParameterSetName = "All")]
        [switch]$IncludeFree,
        [NtCoreLib.MemoryType]$Type = "All",
        [parameter(ParameterSetName = "All")]
        [NtCoreLib.MemoryState]$State = "Commit, Reserve",
        [parameter(ParameterSetName = "All")]
        [string]$Name
    )
    switch ($PsCmdlet.ParameterSetName) {
        "FromAddress" {
            $Process.QueryMemoryInformation($Address) | Write-Output
        }
        "All" {
            if ($IncludeFree) {
                $State = $State -bor "Free"
            }
            if ($Name -ne "") {
                $Process.QueryAllMemoryInformation($Type, $State) | Where-Object Name -eq $Name | Write-Output
            }
            else {
                $Process.QueryAllMemoryInformation($Type, $State) | Write-Output
            }
        }
    }
}

<#
.SYNOPSIS
Set protection flags for a virtual memory region.
.DESCRIPTION
This cmdlet sets protection flags for a region of virtual memory in the current process or another specified process.
.PARAMETER Address
The address location to set the memory protection.
.PARAMETER Size
The size of the memory region to set.
.PARAMETER Process
The process to set the memory in, defaults to current process.
.PARAMETER Protection
Specify the new protection for the memory region.
.OUTPUTS
NtCoreLib.MemoryAllocationProtect - The previous memory protection setting.
.EXAMPLE
Set-NtVirtualMemory $addr 0x1000 ExecuteRead
Sets the protection of a memory region to ExecuteRead.
#>
function Set-NtVirtualMemory {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position = 0)]
        [int64]$Address,
        [parameter(Mandatory, Position = 1)]
        [int64]$Size,
        [parameter(Mandatory, Position = 2)]
        [NtCoreLib.MemoryAllocationProtect]$Protection,
        [NtCoreLib.NtProcess]$Process = [NtCoreLib.NtProcess]::Current
    )
    $Process.ProtectMemory($Address, $Size, $Protection)
}

<#
.SYNOPSIS
Reads bytes from a virtual memory region.
.DESCRIPTION
This cmdlet reads the bytes from a region of virtual memory in the current process or another specified process.
.PARAMETER Address
The address location to read.
.PARAMETER Size
The size of the memory to read. This is the maximum, if the memory address is invalid the returned buffer can be smaller.
.PARAMETER Process
The process to read from, defaults to current process.
.PARAMETER ReadAll
Specify to ensure you read all the requested memory from the process.
.PARAMETER Mapping
Specify a mapped section object.
.PARAMETER Offset
Specify the offset into the mapped section.
.OUTPUTS
byte[] - The array of read bytes. The size of the output might be smaller than the requested size.
.EXAMPLE
Read-NtVirtualMemory $addr 0x1000
Read up to 4096 from $addr.
.EXAMPLE
Read-NtVirtualMemory $addr 0x1000 -Process $process
Read up to 4096 from $addr in another process.
.EXAMPLE
Read-NtVirtualMemory $addr 0x1000 -ReadAll
Read up to 4096 from $addr, fail if can't read all the bytes.
.EXAMPLE
Read-NtVirtualMemory $map -Offset 100 -Size 512
Read up to 512 bytes from offset 100 into a mapped file.
#>
function Read-NtVirtualMemory {
    [CmdletBinding(DefaultParameterSetName="FromAddress")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName="FromAddress")]
        [int64]$Address,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromMapping")]
        [NtCoreLib.NtMappedSection]$Mapping,
        [parameter(ParameterSetName="FromMapping")]
        [int64]$Offset = 0,
        [parameter(Mandatory, Position = 1)]
        [int]$Size,
        [parameter(ParameterSetName="FromAddress")]
        [NtCoreLib.NtProcess]$Process = [NtCoreLib.NtProcess]::Current,
        [switch]$ReadAll
    )

    if ($PSCmdlet.ParameterSetName -eq "FromMapping") {
        $Address = $Mapping.BaseAddress + $Offset
        $Process = $Mapping.Process
    }
    $Process.ReadMemory($Address, $Size, $ReadAll)
}

<#
.SYNOPSIS
Writes bytes to a virtual memory region.
.DESCRIPTION
This cmdlet writes bytes to a region of virtual memory in the current process or another specified process.
.PARAMETER Address
The address location to write.
.PARAMETER Data
The data buffer to write.
.PARAMETER Process
The process to write to, defaults to current process.
.PARAMETER Mapping
Specify a mapped section object.
.PARAMETER Offset
Specify the offset into the mapped section.
.PARAMETER Win32
Specify to use the Win32 WriteProcessMemory API which will automatically change page permissions.
.OUTPUTS
int - The length of bytes successfully written.
.EXAMPLE
Write-NtVirtualMemory $addr 0, 1, 2, 3, 4
Write 5 bytes to $addr
.EXAMPLE
Write-NtVirtualMemory $addr 0, 1, 2, 3, 4 -Process $process
Write 5 bytes to $addr in another process.
.EXAMPLE
Write-NtVirtualMemory $map -Offset 100 -Data 0, 1, 2, 3, 4
Write 5 bytes to a mapping at offset 100.
#>
function Write-NtVirtualMemory {
    [CmdletBinding(DefaultParameterSetName="FromAddress")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName="FromAddress")]
        [int64]$Address,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromMapping")]
        [NtCoreLib.NtMappedSection]$Mapping,
        [parameter(ParameterSetName="FromMapping")]
        [int64]$Offset = 0,
        [parameter(Mandatory, Position = 1)]
        [byte[]]$Data,
        [parameter(ParameterSetName="FromAddress")]
        [NtCoreLib.NtProcess]$Process = [NtCoreLib.NtProcess]::Current,
        [switch]$Win32
    )

    if ($PSCmdlet.ParameterSetName -eq "FromMapping") {
        $Address = $Mapping.BaseAddress + $Offset
        $Process = $Mapping.Process
    }

    if ($Win32) {
        [NtCoreLib.Win32.Memory.Win32MemoryUtils]::WriteMemory($Process, $Address, $Data)
    } else {
        $Process.WriteMemory($Address, $Data)
    }
}

<#
.SYNOPSIS
Get the names of the Windows Stations in the current Session.
.DESCRIPTION
This cmdlet queries the names of the Window Stations in the current Session.
.PARAMETER Current
Show the current Window Station name only.
.INPUTS
string
.OUTPUTS
None
#>
function Get-NtWindowStationName {
    Param(
        [Parameter()]
        [switch]$Current
    )

    if ($Current) {
        [NtCoreLib.NtWindowStation]::Current.Name | Write-Output
    }
    else {
        [NtCoreLib.NtWindowStation]::WindowStations | Write-Output
    }
}

<#
.SYNOPSIS
Gets the names of the Desktops from the specified Window Station.
.DESCRIPTION
This cmdlet queries the names of the Desktops from the specified Window Station.
By default will use the current process Window Station.
.PARAMETER WindowStation
The Window Station to query.
.PARAMETER Current
Specify to get the name of the current thread desktop.
.PARAMETER ThreadId
Specify to get the name of the desktop from a thread.
.INPUTS
string
.OUTPUTS
None
#>
function Get-NtDesktopName {
    [CmdletBinding(DefaultParameterSetName = "FromCurrentWindowStation")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromWindowStation")]
        [NtCoreLib.NtWindowStation]$WindowStation,
        [Parameter(ParameterSetName = "FromCurrentDesktop")]
        [switch]$Current,
        [Parameter(ParameterSetName = "FromThreadId")]
        [alias("tid")]
        [int]$ThreadId
    )

    switch ($PSCmdlet.ParameterSetName) {
        "FromCurrentWindowStation" {
            $winsta = [NtCoreLib.NtWindowStation]::Current
            $winsta.Desktops | Write-Output
        }
        "FromWindowStation" {
            $WindowStation.Desktops | Write-Output
        }
        "FromCurrentDesktop" {
            [NtCoreLib.NtDesktop]::Current.Name | Write-Output
        }
        "FromThreadId" {
            [NtCoreLib.NtDesktop]::GetThreadDesktop($ThreadId).Name | Write-Output
        }
    }
}

<#
.SYNOPSIS
Gets the a list of Window handles.
.DESCRIPTION
This cmdlet queries the list of Window Handles based on a set of criteria such as Desktop or ThreadId.
.PARAMETER Desktop
The Desktop to query.
.PARAMETER Parent
Specify the parent Window if enumerating children.
.PARAMETER Children
Specify the get list of child windows.
.PARAMETER Immersive
Specify to get immersive Windows.
.PARAMETER ThreadId
Specify the thread ID for the Window.
.PARAMETER ProcessId
Specify the process ID for the Window.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtWindow
#>
function Get-NtWindow {
    [CmdletBinding()]
    Param(
        [NtCoreLib.NtDesktop]$Desktop,
        [switch]$Children,
        [switch]$Immersive,
        [NtCoreLib.NtWindow]$Parent = [NtCoreLib.NtWindow]::Null,
        [alias("tid")]
        [int]$ThreadId,
        [alias("pid")]
        [int]$ProcessId
    )

    $ws = [NtCoreLib.NtWindow]::GetWindows($Desktop, $Parent, $Children, !$Immersive, $ThreadId)
    if ($ProcessId -ne 0) {
         $ws = $ws | Where-Object ProcessId -eq $ProcessId
    }
    $ws | Write-Output
}

<#
.SYNOPSIS
Send a message to a Window handle.
.DESCRIPTION
This cmdlet sends a message to a window handle.
.PARAMETER Window
The Window to send to.
.PARAMETER Message
Specify the message to send.
.PARAMETER WParam
Specify the WPARAM value.
.PARAMETER LParam
Specify the LPARAM value.
.PARAMETER Wait
Specify to send the message and wait rather than post.
.PARAMETER Ansi
Specify to send the message as ANSI rather than Unicode.
.INPUTS
None
.OUTPUTS
System.IntPtr
#>
function Send-NtWindowMessage {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.NtWindow[]]$Window,
        [Parameter(Mandatory, Position = 1)]
        [int]$Message,
        [Parameter(Position = 2)]
        [IntPtr]$WParam = [IntPtr]::Zero,
        [Parameter(Position = 3)]
        [IntPtr]$LParam = [IntPtr]::Zero,
        [switch]$Wait,
        [switch]$Ansi
    )

    PROCESS {
        foreach($w in $Window) {
            if ($Wait) {
                if ($Ansi) {
                    $w.SendMessageAnsi($Message, $WParam, $LParam) | Write-Output
                } else {
                    $w.SendMessage($Message, $WParam, $LParam) | Write-Output
                }
            } else {
                if ($Ansi) {
                    $w.PostMessageAnsi($Message, $WParam, $LParam)
                } else {
                    $w.PostMessage($Message, $WParam, $LParam)
                }
            }
        }
    }
}

<#
.SYNOPSIS
Get an ATOM object.
.DESCRIPTION
This cmdlet gets all ATOM objects or by name or atom.
.PARAMETER Atom
Specify the ATOM to get.
.PARAMETER Name
Specify the name of the ATOM to get.
.PARAMETER User
Specify to get a user atom rather than a global.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtAtom
#>
function Get-NtAtom {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [Parameter(Mandatory, ParameterSetName = "FromAtom")]
        [uint16]$Atom,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromName")]
        [string]$Name,
        [Parameter(ParameterSetName = "All")]
        [Parameter(ParameterSetName = "FromAtom")]
        [switch]$User
    )

    switch ($PSCmdlet.ParameterSetName) {
        "All" { [NtCoreLib.NtAtom]::GetAtoms(!$User) | Write-Output }
        "FromAtom" { [NtCoreLib.NtAtom]::Open($Atom, $true, !$User, $true).Result | Write-Output }
        "FromName" { [NtCoreLib.NtAtom]::Find($Name) | Write-Output }
    }
}

<#
.SYNOPSIS
Add a ATOM object.
.DESCRIPTION
This cmdlet adds an ATOM objects.
.PARAMETER Name
Specify the name of the ATOM to add.
.PARAMETER Flags
Specify the flags for the ATOM.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtAtom
#>
function Add-NtAtom {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,
        [NtCoreLib.AddAtomFlags]$Flags = 0
    )

    [NtCoreLib.NtAtom]::Add($Name, $Flags) | Write-Output
}

<#
.SYNOPSIS
Removes an ATOM object.
.DESCRIPTION
This cmdlet removes an ATOM object by name or atom.
.PARAMETER Object
Specify the NtAtom object to remove.
.PARAMETER Atom
Specify the ATOM to remove.
.PARAMETER Name
Specify the name of the ATOM to remove.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-NtAtom {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromObject")]
        [NtCoreLib.NtAtom]$Object,
        [Parameter(Mandatory, ParameterSetName = "FromAtom")]
        [uint16]$Atom,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromName")]
        [string]$Name
    )

    $obj = switch ($PSCmdlet.ParameterSetName) {
        "FromObject" { $Object }
        "FromAtom" { Get-NtAtom -Atom $Atom }
        "FromName" { Get-NtATom -Name $Name }
    }

    if ($null -ne $obj) {
        $obj.Delete()
    }
}

$protseq_completer = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    @("ncalrpc", "ncacn_np", "ncacn_ip_tcp", "ncacn_http", "ncacn_hvsocket") | Where-Object { $_ -like "$wordToComplete*" }
}

<#
.SYNOPSIS
Get a list of ALPC Ports that can be opened by a specified token.
.DESCRIPTION
This cmdlet checks for all ALPC ports on the system and tries to determine if one or more specified tokens can connect to them.
If no tokens are specified then the current process token is used. This function searches handles for existing ALPC Port servers as you can't directly open the server object and just connecting might show inconsistent results.
.PARAMETER ProcessId
Specify a list of process IDs to open for their tokens.
.PARAMETER ProcessName
Specify a list of process names to open for their tokens.
.PARAMETER ProcessCommandLine
Specify a list of command lines to filter on find for the process tokens.
.PARAMETER Token
Specify a list token objects.
.PARAMETER Process
Specify a list process objects to use for their tokens.
.INPUTS
None
.OUTPUTS
NtObjectManager.Cmdlets.Accessible.CommonAccessCheckResult
.NOTES
For best results run this function as an administrator with SeDebugPrivilege available.
.EXAMPLE
Get-AccessibleAlpcPort
Get all ALPC Ports connectable by the current token.
.EXAMPLE
Get-AccessibleAlpcPort -ProcessIds 1234,5678
Get all ALPC Ports connectable by the process tokens of PIDs 1234 and 5678
#>
function Get-AccessibleAlpcPort {
    Param(
        [alias("ProcessIds")]
        [Int32[]]$ProcessId,
        [alias("ProcessNames")]
        [string[]]$ProcessName,
        [alias("ProcessCommandLines")]
        [string[]]$ProcessCommandLine,
        [alias("Tokens")]
        [NtCoreLib.NtToken[]]$Token,
        [alias("Processes")]
        [NtCoreLib.NtProcess[]]$Process
    )
    $access = Get-NtAccessMask -AlpcPortAccess Connect -ToGenericAccess
    Get-AccessibleObject -FromHandle -ProcessId $ProcessId -ProcessName $ProcessName `
        -ProcessCommandLine $ProcessCommandLine -Token $Token -Process $Process -TypeFilter "ALPC Port" -AccessRights $access
}

<#
.SYNOPSIS
Gets the endpoints for a RPC interface from the local endpoint mapper or by brute force.
.DESCRIPTION
This cmdlet gets the endpoints for a RPC interface from the local endpoint mapper. Not all RPC interfaces
are registered in the endpoint mapper so it might not show. You can use the -FindAlpcPort command to try
and brute force an ALPC port for the interface.
.PARAMETER InterfaceId
The UUID of the RPC interface.
.PARAMETER InterfaceVersion
The version of the RPC interface.
.PARAMETER Server
Parsed NDR server.
.PARAMETER Binding
A RPC binding string to query all endpoints from.
.PARAMETER AlpcPort
An ALPC port name. Can contain a full path as long as the string contains \RPC Control\ (case sensitive).
.PARAMETER FindAlpcPort
Use brute force to find a valid ALPC endpoint for the interface.
.PARAMETER ProcessId
Used to find all ALPC ports in a process and get the supported interfaces.
.INPUTS
None or NtCoreLib.Ndr.Rpc.RpcServerInterface
.OUTPUTS
NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpoint[]
.EXAMPLE
Get-RpcEndpoint
Get all RPC registered RPC endpoints.
.EXAMPLE
Get-RpcEndpoint $Server
Get RPC endpoints for a parsed NDR server interface.
.EXAMPLE
Get-RpcEndpoint "A57A4ED7-0B59-4950-9CB1-E600A665154F"
Get RPC endpoints for a specified interface ID ignoring the version.
.EXAMPLE
Get-RpcEndpoint "A57A4ED7-0B59-4950-9CB1-E600A665154F" "1.0"
Get RPC endpoints for a specified interface ID and version.
.EXAMPLE
Get-RpcEndpoint "A57A4ED7-0B59-4950-9CB1-E600A665154F" "1.0" -FindAlpcPort
Get ALPC RPC endpoints for a specified interface ID and version by brute force.
.EXAMPLE
Get-RpcEndpoint -Binding "ncalrpc:[RPC_PORT]"
Get RPC endpoints for exposed over ncalrpc with name RPC_PORT.
.EXAMPLE
Get-RpcEndpoint -AlpcPort "RPC_PORT"
Get RPC endpoints for exposed over ALPC with name RPC_PORT.
.EXAMPLE
Get-RpcEndpoint -ProcessId 1234
Get RPC endpoints for exposed over ALPC for the process 1234.
#>
function Get-RpcEndpoint {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromId")]
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromIdAndVersion")]
        [Guid]$InterfaceId,
        [parameter(Mandatory, Position = 1, ParameterSetName = "FromIdAndVersion")]
        [NtCoreLib.Ndr.Rpc.RpcVersion]$InterfaceVersion,
        [parameter(Mandatory, ParameterSetName = "FromRpcServer", ValueFromPipeline)]
        [NtCoreLib.Ndr.Rpc.RpcServerInterface]$Server,
        [parameter(Mandatory, ParameterSetName = "FromBinding")]
        [NtCoreLib.Win32.Rpc.EndpointMapper.RpcStringBinding]$Binding,
        [parameter(Mandatory, ParameterSetName = "FromAlpc")]
        [string]$AlpcPort,
        [parameter(Mandatory, ParameterSetName = "FromProcessId")]
        [alias("pid")]
        [int]$ProcessId,
        [parameter(Mandatory, ParameterSetName = "FromServiceName")]
        [string]$ServiceName,
        [parameter(ParameterSetName = "FromIdAndVersion")]
        [parameter(ParameterSetName = "FromRpcServer")]
        [switch]$FindAlpcPort,
        [parameter(ParameterSetName = "All")]
        [parameter(ParameterSetName = "FromId")]
        [parameter(ParameterSetName = "FromIdAndVersion")]
        [parameter(ParameterSetName = "FromRpcClient")]
        [NtCoreLib.Win32.Rpc.EndpointMapper.RpcStringBinding]$SearchBinding,
        [parameter(ParameterSetName = "All")]
        [parameter(ParameterSetName = "FromId")]
        [parameter(ParameterSetName = "FromIdAndVersion")]
        [parameter(ParameterSetName = "FromRpcClient")]
        [string[]]$ProtocolSequence = @(),
        [parameter(Mandatory, ParameterSetName = "FromRpcClient")]
        [NtCoreLib.Win32.Rpc.Client.RpcClientBase]$Client
    )

    PROCESS {
        $eps = switch ($PsCmdlet.ParameterSetName) {
            "All" {
                [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpointMapper]::QueryAllEndpoints($SearchBinding)
            }
            "FromId" {
                [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpointMapper]::QueryEndpointsForInterface($SearchBinding, $InterfaceId)
            }
            "FromIdAndVersion" {
                $syntax_id = [NtCoreLib.Ndr.Rpc.RpcSyntaxIdentifier]::new($InterfaceId, $InterfaceVersion)
                if ($FindAlpcPort) {
                    [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpointMapper]::FindAlpcEndpointForInterface($syntax_id)
                }
                else {
                    [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpointMapper]::QueryEndpointsForInterface($SearchBinding, $syntax_id)
                }
            }
            "FromRpcServer" {
                if ($FindAlpcPort) {
                    [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpointMapper]::FindAlpcEndpointForInterface($Server)
                }
                else {
                    $Server.Endpoints | Write-Output
                }
            }
            "FromBinding" {
                [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpointMapper]::QueryEndpointsForBinding($Binding)
            }
            "FromAlpc" {
                [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpointMapper]::QueryEndpointsForAlpcPort($AlpcPort)
            }
            "FromRpcClient" {
                [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpointMapper]::QueryEndpointsForInterface($SearchBinding, $Client.InterfaceId)
            }
            "FromProcessId" {
                (Get-RpcAlpcServer -ProcessId $ProcessId).Endpoints
            }
            "FromServiceName" {
                try {
                    $service = Get-Win32Service -Name $ServiceName
                    if ($service.ProcessId -eq 0) {
                        throw "Service $ServiceName is not running."
                    }
                    Get-RpcEndPoint -ProcessId $service.ProcessId
                } catch {
                    Write-Error $_
                }
            }
        }

        if ($ProtocolSequence.Count -gt 0) {
            $eps = $eps | Where-Object {$_.ProtocolSequence -in $ProtocolSequence}
        }
        $eps | Write-Output
    }
}

Register-ArgumentCompleter -CommandName Get-RpcEndpoint -ParameterName ProtocolSequence -ScriptBlock $protseq_completer

<#
.SYNOPSIS
Get the RPC servers from a DLL.
.DESCRIPTION
This cmdlet parses the RPC servers from a DLL. Note that in order to parse 32 bit DLLs you must run this module in 32 bit PowerShell.
.PARAMETER FullName
The path to the DLL.
.PARAMETER DbgHelpPath
Specify path to a dbghelp DLL to use for symbol resolving. This should be ideally the dbghelp from debugging tool for Windows
which will allow symbol servers however you can use the system version if you just want to pull symbols locally.
.PARAMETER SymbolPath
Specify path for the symbols. If not specified it will first use the _NT_SYMBOL_PATH environment variable then use the
default of 'srv*https://msdl.microsoft.com/download/symbols'
.PARAMETER AsText
Return the results as text rather than objects.
.PARAMETER RemoveComments
When outputing as text remove comments from the output.
.PARAMETER ParseClients
Also parse client interface information, otherwise only servers are returned.
.PARAMETER IgnoreSymbols
Don't resolve any symbol information.
.PARAMETER SerializedPath
Path to a serialized representation of the RPC servers.
.PARAMETER ResolveStructureNames
If private symbols available try and resolve the names of structures and parameters.
.PARAMETER SymSrvFallback
Specify to use a built-in fallback for symbol server resolving when using the system dbghelp DLL. You also need to specify a local cache directory in SymbolPath.
.PARAMETER ProcessId
Specify a process to extract the RPC servers from. This parses all the modules in a process for any available servers.
.PARAMETER ServiceName
Specify the name of a service to extract the RPC servers from.
.INPUTS
string[] List of paths to DLLs.
.OUTPUTS
RpcServer[] The parsed RPC servers.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll
Get the list of RPC servers from rpcss.dll.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll -AsText
Get the list of RPC servers from rpcss.dll, return it as text.
.EXAMPLE
Get-ChildItem c:\windows\system32\*.dll | Get-RpcServer
Get the list of RPC servers from all DLLs in system32, return it as text.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll -DbgHelpPath c:\windbg\x64\dbghelp.dll
Get the list of RPC servers from rpcss.dll, specifying a different DBGHELP for symbol resolving.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll -SymbolPath c:\symbols
Get the list of RPC servers from rpcss.dll, specifying a different symbol path.
.EXAMPLE
Get-RpcServer -SerializedPath rpc.bin
Get the list of RPC servers from the serialized file rpc.bin.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll -SymSrvFallback -SymbolPath c:\symbols
Get the list of RPC servers from rpcss.dll, use symbol server fallback with c:\symbols as the cache directory.
#>
function Get-RpcServer {
    [CmdletBinding(DefaultParameterSetName = "FromDll")]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = "FromDll")]
        [alias("Path")]
        [string]$FullName,
        [parameter(Mandatory, ParameterSetName = "FromSerialized")]
        [string]$SerializedPath,
        [parameter(Mandatory, ParameterSetName = "FromProcessId")]
        [alias("pid")]
        [int]$ProcessId,
        [parameter(Mandatory, ParameterSetName = "FromServiceName")]
        [string]$ServiceName,
        [parameter(ParameterSetName = "FromDll")]
        [parameter(ParameterSetName = "FromProcessId")]
        [parameter(ParameterSetName = "FromServiceName")]
        [string]$DbgHelpPath,
        [parameter(ParameterSetName = "FromDll")]
        [parameter(ParameterSetName = "FromProcessId")]
        [parameter(ParameterSetName = "FromServiceName")]
        [string]$SymbolPath,
        [parameter(ParameterSetName = "FromDll")]
        [switch]$ParseClients,
        [parameter(ParameterSetName = "FromDll")]
        [parameter(ParameterSetName = "FromProcessId")]
        [parameter(ParameterSetName = "FromServiceName")]
        [switch]$IgnoreSymbols,
        [parameter(ParameterSetName = "FromDll")]
        [parameter(ParameterSetName = "FromProcessId")]
        [parameter(ParameterSetName = "FromServiceName")]
        [switch]$ResolveStructureNames,
        [parameter(ParameterSetName = "FromDll")]
        [parameter(ParameterSetName = "FromProcessId")]
        [parameter(ParameterSetName = "FromServiceName")]
        [switch]$SymSrvFallback,
        [switch]$AsText,
        [switch]$RemoveComments
    )

    BEGIN {
        $ParserFlags = [NtCoreLib.Win32.Rpc.Server.RpcServerParserFlags]::None
        if ($ParseClients) {
            $ParserFlags = $ParserFlags -bor [NtCoreLib.Win32.Rpc.Server.RpcServerParserFlags]::ParseClients
        }
        if ($IgnoreSymbols) {
            $ParserFlags = $ParserFlags -bor [NtCoreLib.Win32.Rpc.Server.RpcServerParserFlags]::IgnoreSymbols
        }
        if ($ResolveStructureNames) {
            $ParserFlags = $ParserFlags -bor [NtCoreLib.Win32.Rpc.Server.RpcServerParserFlags]::ResolveStructureNames
        }
        if ($SymSrvFallback) {
            $ParserFlags = $ParserFlags -bor [NtCoreLib.Win32.Rpc.Server.RpcServerParserFlags]::SymSrvFallback
        }
    }

    PROCESS {
        try {
            $servers = switch($PSCmdlet.ParameterSetName) {
                "FromDll" {
                    $FullName = Resolve-Path -LiteralPath $FullName -ErrorAction Stop
                    Write-Progress -Activity "Parsing RPC Servers" -CurrentOperation "$FullName"
                    [NtCoreLib.Win32.Rpc.Server.RpcServer]::ParsePeFile($FullName, $DbgHelpPath, $SymbolPath, $ParserFlags)
                }
                "FromSerialized" {
                    $FullName = Resolve-Path -LiteralPath $SerializedPath -ErrorAction Stop
                    Use-NtObject($stm = [System.IO.File]::OpenRead($FullName)) {
                        while ($stm.Position -lt $stm.Length) {
                            [NtCoreLib.Win32.Rpc.Server.RpcServer]::Deserialize($stm) | Write-Output
                        }
                    }
                }
                "FromProcessId" {
                    $proc = Get-Process -PID $ProcessId
                    if ($null -eq $proc.SafeHandle) {
                        throw "Can't open process $ProcessId"
                    }
                    $proc.Modules | 
                    % { 
                        Get-RpcServer -FullName $_.FileName -DbgHelpPath $DbgHelpPath -SymbolPath $SymbolPath `
                            -IgnoreSymbols:$IgnoreSymbols -ResolveStructureNames:$ResolveStructureNames -SymSrvFallback:$SymSrvFallback 
                    }
                }
                "FromServiceName" {
                    $service = Get-Win32Service -Name $ServiceName
                    if ($service.ProcessId -eq 0) {
                        throw "Service $ServiceName is not running."
                    } else {
                        Get-RpcServer -ProcessId $service.ProcessId -DbgHelpPath $DbgHelpPath -SymbolPath $SymbolPath `
                            -IgnoreSymbols:$IgnoreSymbols -ResolveStructureNames:$ResolveStructureNames -SymSrvFallback:$SymSrvFallback 
                    }
                }
            }

            if ($null -ne $servers) {
                if ($AsText) {
                    foreach ($server in $servers) {
                        $text = $server.FormatAsText($RemoveComments)
                        Write-Output $text
                    }
                }
                else {
                    Write-Output $servers
                }
            }
        }
        catch {
            Write-Error $_
        }
    }
}

<#
.SYNOPSIS
Set a list RPC servers to a file for storage.
.DESCRIPTION
This cmdlet serializes a list of RPC servers to a file. This can be restored using Get-RpcServer -SerializedPath.
.PARAMETER Path
The path to the output file.
.PARAMETER Server
The list of servers to serialize.
.INPUTS
RpcServer[] List of paths to DLLs.
.OUTPUTS
None
.EXAMPLE
Set-RpcServer -Server $server -Path rpc.bin
Serialize servers to file rpc.bin.
#>
function Set-RpcServer {
    Param(
        [parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Win32.Rpc.Server.RpcServer[]]$Server,
        [parameter(Mandatory = $true, Position = 1)]
        [string]$Path
    )

    BEGIN {
        "" | Set-Content -Path $Path
        $Path = Resolve-Path -LiteralPath $Path -ErrorAction Stop
        $stm = [System.IO.File]::Create($Path)
    }

    PROCESS {
        try {
            foreach ($s in $Server) {
                $s.Serialize($stm)
            }
        }
        catch {
            Write-Error $_
        }
    }

    END {
        $stm.Close()
    }
}

<#
.SYNOPSIS
Format the RPC servers as text.
.DESCRIPTION
This cmdlet formats a list of RPC servers as text.
.PARAMETER RpcServer
The RPC servers to format.
.PARAMETER RemoveComments
Specify to remove comments from the output.
.PARAMETER DisableTypeDefs
Specify to not use typedefs in the output.
.PARAMETER Format
Format output in a different language type.
.INPUTS
RpcServer[] The RPC servers to format.
.OUTPUTS
string[] The formatted RPC servers.
.EXAMPLE
Format-RpcServer $rpc
Format list of RPC servers in $rpc.
.EXAMPLE
Format-RpcServer $rpc -RemoveComments
Format list of RPC servers in $rpc without comments.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll | Format-RpcServer
Get the list of RPC servers from rpcss.dll and format them.
#>
function Format-RpcServer {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Win32.Rpc.Server.RpcServer[]]$RpcServer,
        [switch]$RemoveComments,
        [switch]$DisableTypeDefs,
        [NtCoreLib.Ndr.Formatter.NdrFormatterTextFormat]$Format = "Idl"
    )

    PROCESS {
        $flags = if ($DisableTypeDefs) {
            [NtCoreLib.Ndr.Formatter.NdrFormatterFlags]::None
        } else {
            [NtCoreLib.Ndr.Formatter.NdrFormatterFlags]::EnableTypeDefs
        }
        if ($RemoveComments) {
            $flags = $flags -bor [NtCoreLib.Ndr.Formatter.NdrFormatterFlags]::RemoveComments
        }
        foreach ($server in $RpcServer) {
            $server.FormatAsText($flags, $Format) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Gets a list of ALPC RPC servers.
.DESCRIPTION
This cmdlet gets a list of ALPC RPC servers. This relies on being able to access the list of ALPC ports in side a process so might need elevated privileges.
.PARAMETER ProcessId
The ID of a process to query for ALPC servers.
.PARAMETER AlpcPort
The path to the ALPC port to query.
.PARAMETER IgnoreComInterface
Ignore COM only interfaces.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Rpc.Server.RpcAlpcServer[]
.EXAMPLE
Get-RpcAlpcServer
Get all ALPC RPC servers.
.EXAMPLE
Get-RpcAlpcServer -ProcessId 1234
Get all ALPC RPC servers in process ID 1234.
.EXAMPLE
Get-RpcAlpcServer -AlpcPort "\RPC Control\srvsvc"
Get the ALPC RPC servers for the srvsvc ALPC port. Needs Windows 10 19H1 and above to work.
#>
function Get-RpcAlpcServer {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromProcessId")]
        [int]$ProcessId,
        [parameter(Mandatory, ParameterSetName = "FromAlpc")]
        [string]$AlpcPort,
        [switch]$IgnoreComInterface
    )

    Set-NtTokenPrivilege SeDebugPrivilege | Out-Null
    switch ($PsCmdlet.ParameterSetName) {
        "All" {
            [NtCoreLib.Win32.Rpc.Server.RpcAlpcServer]::GetAlpcServers($IgnoreComInterface)
        }
        "FromProcessId" {
            [NtCoreLib.Win32.Rpc.Server.RpcAlpcServer]::GetAlpcServers($ProcessId, $IgnoreComInterface)
        }
        "FromAlpc" {
            [NtCoreLib.Win32.Rpc.Server.RpcAlpcServer]::GetAlpcServer($AlpcPort, $IgnoreComInterface)
        }
    }
}

<#
.SYNOPSIS
Get a RPC client object based on a parsed RPC server.
.DESCRIPTION
This cmdlet creates a new RPC client from a parsed RPC server. The client object contains methods
to call RPC methods. The client starts off disconnected. You need to pass the client to Connect-RpcClient to
connect to the server. If you specify an interface ID and version then a generic client will be created which
allows simple calls to be made without requiring the NDR data.
.PARAMETER Server
Specify the RPC server to base the client on.
.PARAMETER NamespaceName
Specify the name of the compiled namespace for the client.
.PARAMETER ClientName
Specify the class name of the compiled client.
.PARAMETER IgnoreCache
Specify to ignore the compiled client cache and regenerate the source code.
.PARAMETER InterfaceId
Specify the interface ID for a generic client.
.PARAMETER InterfaceVersion
Specify the interface version for a generic client.
.PARAMETER Provider
Specify a Code DOM provider. Defaults to C#.
.PARAMETER Flags
Specify optional flags for the built client class.
.PARAMETER EnableDebugging
Specify to enable debugging on the compiled code.
.PARAMETER UseAddType
Specify to try and use the Add-Type command instead of the C# compiler to build the client.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Rpc.Client.RpcClientBase
.EXAMPLE
Get-RpcClient -Server $Server
Create a new RPC client from a parsed RPC server.
#>
function Get-RpcClient {
    [CmdletBinding(DefaultParameterSetName = "FromServer")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromServer", ValueFromPipeline)]
        [NtCoreLib.Win32.Rpc.Server.RpcServer]$Server,
        [parameter(ParameterSetName = "FromServer")]
        [string]$NamespaceName,
        [parameter(ParameterSetName = "FromServer")]
        [string]$ClientName,
        [parameter(ParameterSetName = "FromServer")]
        [switch]$IgnoreCache,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromIdAndVersion")]
        [string]$InterfaceId,
        [parameter(Mandatory, Position = 1, ParameterSetName = "FromIdAndVersion")]
        [NtCoreLib.Ndr.Rpc.RpcVersion]$InterfaceVersion,
        [parameter(ParameterSetName = "FromServer")]
        [System.CodeDom.Compiler.CodeDomProvider]$Provider,
        [parameter(ParameterSetName = "FromServer")]
        [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilderFlags]$Flags = "GenerateConstructorProperties, StructureReturn, HideWrappedMethods, UnsignedChar, NoNamespace, MarshalPipesAsArrays, GenerateTypeStrictHandles",
        [switch]$EnableDebugging,
        [switch]$UseAddType
    )

    BEGIN {
        if (Get-IsPSCore) {
            if ($null -ne $Provider) {
                Write-Warning "PowerShell Core doesn't support arbitrary providers. Using in-built C#."
            }
            if ([NtObjectManager.Utils.CoreCSharpCodeProvider]::IsSupported) {
                $Provider = New-Object NtObjectManager.Utils.CoreCSharpCodeProvider
            } else {
                $UseAddType = $true
                $AsmName = [NtCoreLib.Win32.Rpc.Client.RpcClientBase].Assembly.FullName
            }
        }
        if ($UseAddType) {
            $Flags = $Flags -band (-bnot [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilderFlags]::NoNamespace)
            $flags = $Flags -bor [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilderFlags]::ExcludeVariableSourceText
        }
    }

    PROCESS {
        if ($PSCmdlet.ParameterSetName -eq "FromServer") {
            if ($UseAddType) {
                $src = Format-RpcClient -Server $Server -ClientName $ClientName -Flags $Flags
                $ts = Add-Type -TypeDefinition $src -ReferencedAssemblies $AsmName,'mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089','System.Collections, Version=0.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a' -PassThru
                foreach($t in $ts) {
                    if ($t.BaseType -eq [NtCoreLib.Win32.Rpc.Client.RpcClientBase]) {
                        New-Object $t.AssemblyQualifiedName
                        break
                    }
                }
            } else {
                $args = [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilderArguments]::new();
                $args.NamespaceName = $NamespaceName
                $args.ClientName = $ClientName
                $args.Flags = $Flags
                $args.EnableDebugging = $EnableDebugging

                [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilder]::CreateClient($Server, $args, $IgnoreCache, $Provider)
            }
        }
        else {
            [NtCoreLib.Win32.Rpc.Client.RpcClient]::new($InterfaceId, $InterfaceVersion)
        }
    }
}

<#
.SYNOPSIS
Connects a RPC client to an endpoint.
.DESCRIPTION
This cmdlet connects a RPC client to an endpoint. You can specify what transport to use based on the protocol sequence.
.PARAMETER Client
Specify the RPC client to connect.
.PARAMETER ProtocolSequence
Specify the RPC protocol sequence this client will connect through.
.PARAMETER EndpointPath
Specify the endpoint string. If not specified this will lookup the endpoint from the endpoint mapper.
.PARAMETER NetworkAddress
Specify the network address. If not specified the local system will be used.
.PARAMETER SecurityQualityOfService
Specify the security quality of service for the connection.
.PARAMETER Credentials
Specify user credentials for the RPC client authentication.
.PARAMETER ServicePrincipalName
Specify service principal name for the RPC client authentication.
.PARAMETER AuthenticationLevel
Specify authentication level for the RPC client authentication.
.PARAMETER AuthenticationType
Specify authentication type for the RPC client authentication.
.PARAMETER AuthenticationCapabilities
Specify authentication capabilities for the RPC client authentication.
.PARAMETER PassThru
Specify to the pass the client object to the output.
.PARAMETER FindAlpcPort
Specify to search for an ALPC port for the RPC client.
.PARAMETER Force
Specify to for the client to connect even if the client is already connected to another transport.
.PARAMETER Configuration
Specify low-level transport configuration.
.INPUTS
NtCoreLib.Win32.Rpc.Client.RpcClientBase[]
.OUTPUTS
NtCoreLib.Win32.Rpc.Client.RpcClientBase[]
.EXAMPLE
Connect-RpcClient -Client $Client
Connect an RPC ALPC client, looking up the path using the endpoint mapper.
.EXAMPLE
Connect-RpcClient -Client $Client -EndpointPath "\RPC Control\ABC"
Connect an RPC ALPC client with an explicit path.
.EXAMPLE
Connect-RpcClient -Client $Client -SecurityQualityOfService $(New-NtSecurityQualityOfService -ImpersonationLevel Anonymous)
Connect an RPC ALPC client with anonymous impersonation level.
.EXAMPLE
Connect-RpcClient -Client $Client -ProtocolSequence "ncalrpc"
Connect an RPC ALPC client from a specific protocol sequence.
.EXAMPLE
Connect-RpcClient -Client $Client -Endpoint $ep
Connect an RPC client to a specific endpoint.
.EXAMPLE
Connect-RpcClient -Client $Client -FindAlpcPort
Connect an RPC ALPC client, looking up the path using brute force.
#>
function Connect-RpcClient {
    [CmdletBinding(DefaultParameterSetName = "FromProtocol")]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Win32.Rpc.Client.RpcClientBase]$Client,
        [parameter(Position = 1, ParameterSetName = "FromProtocol")]
        [string]$EndpointPath,
        [parameter(ParameterSetName = "FromProtocol")]
        [string]$ProtocolSequence = "ncalrpc",
        [parameter(ParameterSetName = "FromProtocol")]
        [string]$NetworkAddress,
        [parameter(Position = 1, Mandatory, ParameterSetName = "FromEndpoint")]
        [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpoint]$Endpoint,
        [parameter(Mandatory, ParameterSetName = "FromFindEndpoint")]
        [switch]$FindAlpcPort,
        [parameter(ParameterSetName = "FromBindingString")]
        [NtCoreLib.Win32.Rpc.EndpointMapper.RpcStringBinding]$StringBinding,
        [NtCoreLib.Security.Token.SecurityQualityOfService]$SecurityQualityOfService,
        [NtCoreLib.Win32.Security.Authentication.AuthenticationCredentials]$Credentials,
        [string]$ServicePrincipalName,
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationLevel]$AuthenticationLevel = "None",
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationType]$AuthenticationType = "None",
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationCapabilities]$AuthenticationCapabilities = "None",
        [NtCoreLib.Win32.Rpc.Transport.RpcClientTransportConfiguration]$Configuration,
        [switch]$PassThru,
        [switch]$Force
    )

    BEGIN {
        $security = New-RpcTransportSecurity -SecurityQualityOfService $SecurityQualityOfService `
            -Credentials $Credentials -ServicePrincipalName $ServicePrincipalName `
            -AuthenticationLevel $AuthenticationLevel -AuthenticationType $AuthenticationType `
            -AuthenticationCapabilities $AuthenticationCapabilities
    }

    PROCESS {
        if ($Force) {
            Disconnect-RpcClient -Client $Client
        }
        switch ($PSCmdlet.ParameterSetName) {
            "FromProtocol" {
                $Client.Connect($ProtocolSequence, $EndpointPath, $NetworkAddress, $security, $Configuration)
            }
            "FromEndpoint" {
                $Client.Connect($Endpoint, $security, $Configuration)
            }
            "FromFindEndpoint" {
                foreach ($ep in $(Get-ChildItem "NtObject:\RPC Control")) {
                    try {
                        $name = $ep.Name
                        Write-Progress -Activity "Finding ALPC Endpoint" -CurrentOperation "$name"
                        $Client.Connect("ncalrpc", $name, [NullString]::Value, $security)
                    }
                    catch {
                        Write-Information $_
                    }
                }
            }
            "FromBindingString" {
                $Client.Connect($StringBinding, $security, $Configuration)
            }
        }

        if ($PassThru) {
            $Client | Write-Output
        }
    }
}

Register-ArgumentCompleter -CommandName Connect-RpcClient -ParameterName ProtocolSequence -ScriptBlock $protseq_completer

<#
.SYNOPSIS
Disconnect an RPC client.
.DESCRIPTION
This cmdlet disconnects a RPC client from an endpoint.
.PARAMETER Client
Specify the RPC client to disconnect.
.PARAMETER PassThru
Specify to the pass the client object to the output.
.INPUTS
NtCoreLib.Win32.Rpc.Client.RpcClientBase[]
.OUTPUTS
NtCoreLib.Win32.Rpc.Client.RpcClientBase[]
.EXAMPLE
Disconnect-RpcClient -Client $Client
Disconnect an RPC ALPC client.
#>
function Disconnect-RpcClient {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Win32.Rpc.Client.RpcClientBase]$Client,
        [switch]$PassThru
    )

    PROCESS {
        $Client.Disconnect()

        if ($PassThru) {
            $Client | Write-Output
        }
    }
}

<#
.SYNOPSIS
Format a RPC client as source code based on a parsed RPC server.
.DESCRIPTION
This cmdlet gets source code for a RPC client from a parsed RPC server.
.PARAMETER Server
Specify the RPC server to base the client on.
.PARAMETER NamespaceName
Specify the name of the compiled namespace for the client.
.PARAMETER ClientName
Specify the class name of the compiled client.
.PARAMETER Flags
Specify to flags for the source creation.
.PARAMETER Provider
Specify a Code DOM provider. Defaults to C#.
.PARAMETER Options
Specify optional options for the code generation if Provider is also specified.
.PARAMETER OutputPath
Specify optional output directory to write formatted client.
.PARAMETER GroupByName
Specify when outputting to a directory to group by the name of the server executable.
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Format-RpcClient -Server $Server
Get the source code for a RPC client from a parsed RPC server.
.EXAMPLE
$servers | Format-RpcClient
Get the source code for RPC clients from a list of parsed RPC servers.
.EXAMPLE
$servers | Format-RpcClient -OutputPath rpc_output
Get the source code for RPC clients from a list of parsed RPC servers and output as separate source code files.
#>
function Format-RpcClient {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Win32.Rpc.Server.RpcServer[]]$Server,
        [string]$NamespaceName,
        [string]$ClientName,
        [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilderFlags]$Flags = 0,
        [System.CodeDom.Compiler.CodeDomProvider]$Provider,
        [System.CodeDom.Compiler.CodeGeneratorOptions]$Options,
        [string]$OutputPath,
        [switch]$GroupByName
    )

    BEGIN {
        $file_ext = "cs"
        if ($null -ne $Provider) {
            $file_ext = $Provider.FileExtension
        }

        if ("" -ne $OutputPath) {
            mkdir $OutputPath -ErrorAction Ignore | Out-Null
        }
    }

    PROCESS {
        $args = [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilderArguments]::new();
        $args.NamespaceName = $NamespaceName
        $args.ClientName = $ClientName
        $args.Flags = $Flags

        foreach ($s in $Server) {
            $src = if ($null -eq $Provider) {
                [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilder]::BuildSource($s, $args)
            }
            else {
                [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilder]::BuildSource($s, $args, $Provider, $Options)
            }

            if ("" -eq $OutputPath) {
                $src | Write-Output
            }
            else {
                if ($GroupByName) {
                    $path = Join-Path -Path $OutputPath -ChildPath $s.Name.ToLower()
                    mkdir $path -ErrorAction Ignore | Out-Null
                } else {
                    $path = $OutputPath
                }
                $path = Join-Path -Path $path -ChildPath "$($s.InterfaceId)_$($s.InterfaceVersion).$file_ext"
                $src | Set-Content -Path $path
            }
        }
    }
}

<#
.SYNOPSIS
Format RPC complex types to an encoder/decoder source code file.
.DESCRIPTION
This cmdlet gets source code for encoding and decoding RPC complex types.
.PARAMETER ComplexType
Specify the list of complex types to format.
.PARAMETER Server
Specify the server containing the list of complex types to format.
.PARAMETER NamespaceName
Specify the name of the compiled namespace for the client.
.PARAMETER EncoderName
Specify the class name of the encoder.
.PARAMETER DecoderName
Specify the class name of the decoder.
.PARAMETER Provider
Specify a Code DOM provider. Defaults to C#.
.PARAMETER Options
Specify optional options for the code generation if Provider is also specified.
.PARAMETER Pointer
Specify to always wrap complex types in an unique pointer.
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Format-RpcComplexType -Server $Server
Get the source code for RPC complex types client from a parsed RPC server.
.EXAMPLE
Format-RpcComplexType -ComplexType $ComplexTypes
Get the source code for RPC complex types client from a list of types.
#>
function Format-RpcComplexType {
    [CmdletBinding(DefaultParameterSetName = "FromTypes")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromTypes")]
        [NtCoreLib.Ndr.Dce.NdrComplexTypeReference[]]$ComplexType,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromServer")]
        [NtCoreLib.Win32.Rpc.Server.RpcServer]$Server,
        [string]$NamespaceName,
        [string]$EncoderName,
        [string]$DecoderName,
        [System.CodeDom.Compiler.CodeDomProvider]$Provider,
        [System.CodeDom.Compiler.CodeGeneratorOptions]$Options,
        [switch]$Pointer
    )

    PROCESS {
        $types = switch ($PsCmdlet.ParameterSetName) {
            "FromTypes" { $ComplexType }
            "FromServer" { $Server.ComplexTypes }
        }
        if ($null -eq $Provider) {
            [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilder]::BuildSource([NtCoreLib.Ndr.Dce.NdrComplexTypeReference[]]$types, $EncoderName, $DecoderName, $NamespaceName, $Pointer) | Write-Output
        }
        else {
            [NtCoreLib.Win32.Rpc.Client.Builder.RpcClientBuilder]::BuildSource([NtCoreLib.Ndr.Dce.NdrComplexTypeReference[]]$types, $EncoderName, $DecoderName, $NamespaceName, $Pointer, $Provider, $Options) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get a new RPC context handle.
.DESCRIPTION
This cmdlet creates a new RPC context handle for calling RPC APIs.
.PARAMETER Uuid
The UUID for the context handle.
.PARAMETER Attributes
The attribute flags for the context handle.
.INPUTS
None
.OUTPUTS
NtCoreLib.Ndr.Marshal.NdrContextHandle
.EXAMPLE
New-RpcContextHandle
Creates a new RPC context handle.
#>
function New-RpcContextHandle {
    param(
        [guid]$Uuid = [guid]::Empty,
        [int]$Attributes = 0
    )
    [NtCoreLib.Ndr.Marshal.NdrContextHandle]::new($Attributes, $Uuid)
}

<#
.SYNOPSIS
Get an RPC string binding from its parts.
.DESCRIPTION
This cmdlet gets an RPC string binding based on its component parts.
.PARAMETER ProtocolSequence
Specify the RPC protocol sequence .
.PARAMETER Endpoint
Specify the endpoint string.
.PARAMETER NetworkAddress
Specify the network address.
.PARAMETER ObjectUuid
Specify the object UUID.
.PARAMETER Options
Specify the options.
.PARAMETER AsObject
Specify to return the binding as an object.
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Get-RpcStringBinding -ProtocolSequence "ncalrpc"
Connect an RPC ALPC string binding from a specific protocol sequence.
#>
function Get-RpcStringBinding {
    [CmdletBinding(DefaultParameterSetName = "FromProtocol")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$ProtocolSequence,
        [parameter(Position = 1)]
        [string]$Endpoint,
        [parameter(Position = 2)]
        [string]$NetworkAddress,
        [parameter(Position = 3)]
        [System.Nullable[Guid]]$ObjectUuid,
        [parameter(Position = 4)]
        [string]$Options,
        [switch]$AsObject
    )

    $binding = [NtCoreLib.Win32.Rpc.EndpointMapper.RpcStringBinding]::new($ProtocolSequence, $NetworkAddress, $Endpoint, $Options, $ObjectUuid)
    if ($AsObject) {
        $binding
    } else {
        $binding.ToString()
    }
}

Register-ArgumentCompleter -CommandName Get-RpcStringBinding -ParameterName ProtocolSequence -ScriptBlock $protseq_completer

<#
.SYNOPSIS
Creates a NDR parser for a process.
.DESCRIPTION
This cmdlet creates a new NDR parser for the given process.
.PARAMETER Process
The process to create the NDR parser on. If not specified then the current process is used.
.PARAMETER SymbolResolver
Specify a symbol resolver for the parser. Note that this should be a resolver for the same process as we're parsing.
.PARAMETER ParserFlags
Specify flags which affect the parsing operation.
.OUTPUTS
NtCoreLib.Ndr.Parser.NdrParser - The NDR parser.
.EXAMPLE
$ndr = New-NdrParser
Get an NDR parser for the current process.
.EXAMPLE
New-NdrParser -Process $p -SymbolResolver $resolver
Get an NDR parser for a specific process with a known resolver.
#>
function New-NdrParser {
    Param(
        [NtCoreLib.NtProcess]$Process,
        [NtCoreLib.Win32.Debugger.Symbols.ISymbolResolver]$SymbolResolver,
        [NtCoreLib.Ndr.Parser.NdrParserFlags]$ParserFlags = 0
    )
    [NtCoreLib.Ndr.Parser.NdrParser]::new($Process, $SymbolResolver, $ParserFlags)
}

function Convert-HashTableToIidNames {
    Param(
        [Hashtable]$IidToName,
        [NtCoreLib.Ndr.Com.ComProxy[]]$Proxy
    )
    $dict = [System.Collections.Generic.Dictionary[Guid, string]]::new()
    if ($null -ne $IidToName) {
        foreach ($pair in $IidToName.GetEnumerator()) {
            $guid = [Guid]::new($pair.Key)
            $dict.Add($guid, $pair.Value)
        }
    }

    if ($null -ne $Proxy) {
        foreach ($p in $Proxy.Interfaces) {
            $dict.Add($p.Iid, $p.Name)
        }
    }

    if (!$dict.ContainsKey("00000000-0000-0000-C000-000000000046")) {
        $dict.Add("00000000-0000-0000-C000-000000000046", "IUnknown")
    }

    if (!$dict.ContainsKey("00020400-0000-0000-C000-000000000046")) {
        $dict.Add("00020400-0000-0000-C000-000000000046", "IDispatch")
    }

    return $dict
}

<#
.SYNOPSIS
Parses COM proxy information from a DLL.
.DESCRIPTION
This cmdlet parses the COM proxy information from a specified DLL.
.PARAMETER Path
The path to the DLL containing the COM proxy information.
.PARAMETER Clsid
Optional CLSID for the object used to find the proxy information.
.PARAMETER Iids
Optional list of IIDs to parse from the proxy information.
.PARAMETER ParserFlags
Specify flags which affect the parsing operation.
.OUTPUTS
The parsed proxy information and complex types.
.EXAMPLE
$p = Get-NdrComProxy c:\path\to\proxy.dll
Parse the proxy information from c:\path\to\proxy.dll
.EXAMPLE
$p = Get-NdrComProxy $env:SystemRoot\system32\combase.dll -Clsid "00000320-0000-0000-C000-000000000046"
Parse the proxy information from combase.dll with a specific proxy CLSID.
.EXAMPLE
$p = Get-NdrComProxy $env:SystemRoot\system32\combase.dll -Clsid "00000320-0000-0000-C000-000000000046" -Iid "00000001-0000-0000-c000-000000000046"
Parse the proxy information from combase.dll with a specific proxy CLSID, only returning a specific IID.
#>
function Get-NdrComProxy {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$Path,
        [Guid]$Clsid = [Guid]::Empty,
        [NtCoreLib.Win32.Debugger.Symbols.ISymbolResolver]$SymbolResolver,
        [Guid[]]$Iid,
        [NtCoreLib.Ndr.Parser.NdrParserFlags]$ParserFlags = 0
    )
    $Path = Resolve-Path $Path -ErrorAction Stop
    Use-NtObject($parser = New-NdrParser -SymbolResolver $SymbolResolver -NdrParserFlags $ParserFlags) {
        $proxies = $parser.ReadFromComProxyFile($Path, $Clsid, $Iid) | Write-Output
        $props = @{
            Path         = $Path;
            Proxies      = $proxies;
            IidToNames   = Convert-HashTableToIidNames -Proxy $proxies;
        }
        $obj = New-Object -TypeName PSObject -Prop $props
        Write-Output $obj
    }
}

<#
.SYNOPSIS
Format an NDR procedure.
.DESCRIPTION
This cmdlet formats a parsed NDR procedure.
.PARAMETER Procedure
The procedure to format.
.PARAMETER IidToName
A dictionary of IID to name mappings for parameters.
.PARAMETER Format
The output text format.
.OUTPUTS
string - The formatted procedure.
.EXAMPLE
Format-NdrProcedure $proc
Format a procedure.
.EXAMPLE
$procs | Format-NdrProcedure
Format a list of procedures from a pipeline.
.EXAMPLE
Format-NdrProcedure $proc -IidToName @{"00000000-0000-0000-C000-000000000046"="IUnknown";}
Format a procedure with a known IID to name mapping.
#>
function Format-NdrProcedure {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline = $true)]
        [NtCoreLib.Ndr.Dce.NdrProcedureDefinition]$Procedure,
        [Hashtable]$IidToName,
        [NtCoreLib.Ndr.Formatter.NdrFormatterTextFormat]$Format = "Idl"
    )

    BEGIN {
        $dict = Convert-HashTableToIidNames($IidToName)
        $formatter = [NtCoreLib.Ndr.Formatter.NdrFormatter]::Create($Format, $dict)
    }

    PROCESS {
        $fmt = $formatter.FormatProcedure($Procedure)
        Write-Output $fmt
    }
}

<#
.SYNOPSIS
Format an NDR complex type.
.DESCRIPTION
This cmdlet formats a parsed NDR complex type.
.PARAMETER ComplexType
The complex type to format.
.PARAMETER IidToName
A dictionary of IID to name mappings for parameters.
.PARAMETER Format
The output text format.
.OUTPUTS
string - The formatted complex type.
.EXAMPLE
Format-NdrComplexType $type
Format a complex type.
.EXAMPLE
$cts | Format-NdrComplexType
Format a list of complex types from a pipeline.
.EXAMPLE
Format-NdrComplexType $type -IidToName @{"00000000-0000-0000-C000-000000000046"="IUnknown";}
Format a complex type with a known IID to name mapping.
#>
function Format-NdrComplexType {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Ndr.Dce.NdrComplexTypeReference[]]$ComplexType,
        [Hashtable]$IidToName,
        [NtCoreLib.Ndr.Formatter.NdrFormatterTextFormat]$Format = "Idl"
    )

    BEGIN {
        $dict = Convert-HashTableToIidNames($IidToName)
        $formatter = [NtCoreLib.Ndr.Formatter.NdrFormatter]::Create($Format, $dict)
    }

    PROCESS {
        foreach ($t in $ComplexType) {
            $formatter.FormatComplexType($t) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Format an NDR COM proxy.
.DESCRIPTION
This cmdlet formats a parsed NDR COM proxy.
.PARAMETER Proxy
The proxy to format.
.PARAMETER IidToName
A dictionary of IID to name mappings for parameters.
.PARAMETER DemangleComName
A script block which demangles a COM name (for WinRT types)
.PARAMETER Format
The output text format.
.OUTPUTS
string - The formatted proxy.
.EXAMPLE
Format-NdrComProxy $proxy
Format a COM proxy.
.EXAMPLE
$proxies | Format-NdrComProxy
Format a list of COM proxies from a pipeline.
.EXAMPLE
Format-NdrComProxy $proxy -IidToName @{"00000000-0000-0000-C000-000000000046"="IUnknown";}
Format a COM proxy with a known IID to name mapping.
#>
function Format-NdrComProxy {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Ndr.Com.ComProxy]$Proxy,
        [Hashtable]$IidToName,
        [ScriptBlock]$DemangleComName,
        [NtCoreLib.Ndr.Formatter.NdrFormatterTextFormat]$Format = "Idl"
    )

    BEGIN {
        $dict = Convert-HashTableToIidNames($IidToName)
    }

    PROCESS {
         $formatter = if ($null -eq $DemangleComName) {
            [NtCoreLib.Ndr.Formatter.NdrFormatter]::Create($Format, $dict)
        }
        else {
            [NtCoreLib.Ndr.Formatter.NdrFormatter]::Create($Format, $dict, [Func[string, string]]$DemangleComName)
        }
        $formatter.ComProxies.AddRange($Proxy.Interfaces)
        $formatter.ComplexTypes.AddRange($Proxy.ComplexTypes)
        $formatter.Format() | Write-Output
    }
}

<#
.SYNOPSIS
Parses RPC server information from an executable.
.DESCRIPTION
This cmdlet parses the RPC server information from a specified executable with a known offset.
.PARAMETER Path
The path to the executable containing the RPC server information.
.PARAMETER Offset
The offset into the executable where the RPC_SERVER_INTERFACE structure is loaded.
.PARAMETER ParserFlags
Specify flags which affect the parsing operation.
.OUTPUTS
The parsed RPC server information and complex types.
.EXAMPLE
$p = Get-NdrRpcServerInterface c:\path\to\server.dll 0x18000
Parse the RPC server information from c:\path\to\proxy.dll with offset 0x18000
#>
function Get-NdrRpcServerInterface {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$Path,
        [parameter(Mandatory, Position = 1)]
        [int]$Offset,
        [NtCoreLib.Win32.Debugger.Symbols.ISymbolResolver]$SymbolResolver,
        [NtCoreLib.Ndr.Parser.NdrParserFlags]$ParserFlags = 0
    )
    $Path = Resolve-Path $Path -ErrorAction Stop
    Use-NtObject($parser = New-NdrParser -SymbolResolver $SymbolResolver -ParserFlags $ParserFlags) {
        $rpc_server = $parser.ReadFromRpcServerInterface($Path, $Offset)
        $props = @{
            Path         = $Path;
            RpcServer    = $rpc_server;
        }
        $obj = New-Object -TypeName PSObject -Prop $props
        Write-Output $obj
    }
}

<#
.SYNOPSIS
Format an RPC server interface type.
.DESCRIPTION
This cmdlet formats a parsed RPC server interface type.
.PARAMETER RpcServer
The RPC server interface to format.
.PARAMETER Format
The output text format.
.OUTPUTS
string - The formatted RPC server interface.
.EXAMPLE
Format-NdrRpcServerInterface $type
Format an RPC server interface type.
#>
function Format-NdrRpcServerInterface {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [NtCoreLib.Ndr.Rpc.RpcServerInterface]$RpcServer,
        [NtCoreLib.Ndr.Formatter.NdrFormatterTextFormat]$Format = "Idl"
    )

    BEGIN {
        $formatter = [NtCoreLib.Ndr.Formatter.NdrFormatter]::Create($Format)
    }

    PROCESS {
        $fmt = $formatter.FormatRpcServerInterface($RpcServer)
        Write-Output $fmt
    }
}

<#
.SYNOPSIS
Get NDR complex types from memory.
.DESCRIPTION
This cmdlet parses NDR complex type information from a location in memory.
.PARAMETER PicklingInfo
Specify pointer to the MIDL_TYPE_PICKLING_INFO structure.
.PARAMETER StubDesc
Specify pointer to the MIDL_STUB_DESC structure.
.PARAMETER StublessProxy
Specify pointer to the MIDL_STUBLESS_PROXY_INFO structure.
.PARAMETER OffsetTable
Specify pointer to type offset table.
.PARAMETER TypeIndex
Specify list of type index into type offset table.
.PARAMETER TypeFormat
Specify list of type format string addresses for the types.
.PARAMETER TypeOffset
Specify list of type offsets into the format string for the types.
.PARAMETER Process
Specify optional process which contains the types.
.PARAMETER Module
Specify optional module base address for the types. If set all pointers
are relative offsets from the module address.
.INPUTS
None
.OUTPUTS
NdrComplexTypeReference[]
#>
function Get-NdrComplexType {
    [CmdletBinding(DefaultParameterSetName="FromDecode3")]
    Param(
        [Parameter(Mandatory)]
        [long]$PicklingInfo,
        [Parameter(Mandatory, ParameterSetName = "FromDecode2")]
        [Parameter(Mandatory, ParameterSetName = "FromDecode2Offset")]
        [long]$StubDesc,
        [Parameter(Mandatory, ParameterSetName = "FromDecode2")]
        [long[]]$TypeFormat,
        [Parameter(Mandatory, ParameterSetName = "FromDecode2Offset")]
        [int[]]$TypeOffset,
        [Parameter(Mandatory, ParameterSetName = "FromDecode3")]
        [long]$StublessProxy,
        [Parameter(Mandatory, ParameterSetName = "FromDecode3")]
        [long]$OffsetTable,
        [Parameter(Mandatory, ParameterSetName = "FromDecode3")]
        [int[]]$TypeIndex,
        [NtCoreLib.Win32.Loader.SafeLoadLibraryHandle]$Module,
        [NtCoreLib.NtProcess]$Process,
        [NtCoreLib.Ndr.Parser.NdrParserFlags]$Flags = "IgnoreUserMarshal"
    )

    $base_address = 0
    if ($null -ne $Module) {
        $base_address = $Module.DangerousGetHandle().ToInt64()
    }

    switch($PSCmdlet.ParameterSetName) {
        "FromDecode2" {
            $type_offset = $TypeFormat | % { $_ + $base_address }
            [NtCoreLib.Ndr.Parser.NdrParser]::ReadPicklingComplexTypes($Process, $PicklingInfo+$base_address,`
                $StubDesc+$base_address, $type_offset, $Flags) | Write-Output
        }
        "FromDecode2Offset" {
            [NtCoreLib.Ndr.Parser.NdrParser]::ReadPicklingComplexTypes($Process, $PicklingInfo+$base_address,`
                $StubDesc+$base_address, $TypeOffset, $Flags) | Write-Output
        }
        "FromDecode3" {
            [NtCoreLib.Ndr.Parser.NdrParser]::ReadPicklingComplexTypes($Process, $PicklingInfo+$base_address,`
                $StublessProxy+$base_address, $OffsetTable+$base_address, $TypeIndex, $Flags) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Gets an ALPC server port.
.DESCRIPTION
This cmdlet gets an ALPC server port by name. As you can't directly open the server end of the port this function goes through
all handles and tries to extract the port from the hosting process. This might require elevated privileges, especially debug
privilege, to work correctly.
.PARAMETER Path
The path to the ALPC server port to get.
.PARAMETER ProcessId
The process ID of the process to query for ALPC servers.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtAlpc
.EXAMPLE
Get-NtAlpcServer
Gets all ALPC server objects accessible to the current process.
.EXAMPLE
Get-NtAlpcServer "\RPC Control\atsvc"
Gets the "\RPC Control\atsvc" ALPC server.
.EXAMPLE
Get-NtAlpcServer -ProcessId 1234
Gets all ALPC servers from PID 1234.
#>
function Get-NtAlpcServer {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromPath")]
        [string]$Path,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromProcessId")]
        [alias("pid")]
        [int]$ProcessId
    )

    if (![NtCoreLib.NtToken]::EnableDebugPrivilege()) {
        Write-Warning "Can't enable debug privilege, results might be incomplete"
    }

    if ($PSCmdlet.ParameterSetName -ne "FromProcessId") {
        $ProcessId = -1
    }
    $hs = Get-NtHandle -ObjectTypes "ALPC Port" -ProcessId $ProcessId | Where-Object Name -ne ""

    switch ($PSCmdlet.ParameterSetName) {
        "All" {
            Write-Output $hs.GetObject()
        }
        "FromProcessId" {
            Write-Output $hs.GetObject()
        }
        "FromPath" {
            foreach ($h in $hs) {
                if ($h.Name -eq $Path) {
                    Write-Output $h.GetObject()
                    break
                }
            }
        }
    }
}

<#
.SYNOPSIS
Add a RPC security context to a client.
.DESCRIPTION
This cmdlet adds a RPC security context to an endpoint.
.PARAMETER Client
Specify the RPC client to add the context to.
.PARAMETER SecurityQualityOfService
Specify the security quality of service for the connection.
.PARAMETER Credentials
Specify user credentials for the RPC client authentication.
.PARAMETER ServicePrincipalName
Specify service principal name for the RPC client authentication.
.PARAMETER AuthenticationLevel
Specify authentication level for the RPC client authentication.
.PARAMETER AuthenticationType
Specify authentication type for the RPC client authentication.
.PARAMETER AuthenticationCapabilities
Specify authentication capabilities for the RPC client authentication.
.PARAMETER PassThru
Specify to the pass the security context object to the output. If you don't specify this
the security context will be set as the current context before returning.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Rpc.Transport.RpcTransportSecurityContext
#>
function Add-RpcClientSecurityContext {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Rpc.Client.RpcClientBase]$Client,
        [NtCoreLib.Security.Token.SecurityQualityOfService]$SecurityQualityOfService,
        [NtCoreLib.Win32.Security.Authentication.AuthenticationCredentials]$Credentials,
        [string]$ServicePrincipalName,
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationLevel]$AuthenticationLevel = "None",
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationType]$AuthenticationType = "None",
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationCapabilities]$AuthenticationCapabilities = "None",
        [switch]$PassThru
    )

    try {
        $security = New-RpcTransportSecurity -SecurityQualityOfService $SecurityQualityOfService `
            -Credentials $Credentials -ServicePrincipalName $ServicePrincipalName `
            -AuthenticationLevel $AuthenticationLevel -AuthenticationType $AuthenticationType `
            -AuthenticationCapabilities $AuthenticationCapabilities
        $ctx = $Client.Transport.AddSecurityContext($security)
        if ($PassThru) {
            $ctx
        } else {
            Set-RpcClientSecurityContext -Client $Client -SecurityContext $ctx
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Set a RPC security context on a client.
.DESCRIPTION
This cmdlet sets the current RPC security context for a client.
.PARAMETER Client
Specify the RPC client to set the context to.
.PARAMETER SecurityContext
Specify the security context to set.
.PARAMETER ContextId
Specify the ID of the security context to set.
.INPUTS
None
.OUTPUTS
None
#>
function Set-RpcClientSecurityContext {
    [CmdletBinding(DefaultParameterSetName="FromContext")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Rpc.Client.RpcClientBase]$Client,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromContext")]
        [NtCoreLib.Win32.Rpc.Transport.RpcTransportSecurityContext]$SecurityContext,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromId")]
        [int]$ContextId
    )

    if ($PSCmdlet.ParameterSetName -eq "FromId") {
        $SecurityContext = Get-RpcClientSecurityContext -Client $Client -ContextId $ContextId
    }

    $Client.Transport.CurrentSecurityContext = $SecurityContext
}

<#
.SYNOPSIS
Get a RPC security contexts from a client.
.DESCRIPTION
This cmdlet gets the current RPC security context for a client.
.PARAMETER Client
Specify the RPC client to set the context to.
.PARAMETER Current
Specify to return the current context only.
.PARAMETER ContextId
Specify to return the context with the specified ID.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Rpc.Transport.RpcTransportSecurityContext[]
#>
function Get-RpcClientSecurityContext {
    [CmdletBinding(DefaultParameterSetName="All")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Rpc.Client.RpcClientBase]$Client,
        [parameter(Mandatory, ParameterSetName="FromCurrent")]
        [switch]$Current,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromId")]
        [int]$ContextId
    )

    switch($PSCmdlet.ParameterSetName) {
        "All" {
            $Client.Transport.SecurityContext | Write-Output
        }
        "FromCurrent" {
            $Client.Transport.CurrentSecurityContext
        }
        "FromId" {
            $Client.Transport.SecurityContext | Where-Object ContextId -eq $ContextId
        }
    }
}

<#
.SYNOPSIS
Get the registered service principal name for a RPC server.
.DESCRIPTION
This cmdlet gets the registered service principal name for a RPC server.
.PARAMETER Binding
Specify the server binding.
.PARAMETER AuthenticationType
Specify the authentication type.
.PARAMETER UseManagedClient
Specify to use a managed client.
.PARAMETER Security
Specify security to use with a managed client.
.INPUTS
None
.OUTPUTS
string
#>
function Get-RpcServicePrincipalName {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Rpc.EndpointMapper.RpcStringBinding]$Binding,
        [parameter(Mandatory, Position = 1)]
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationType]$AuthenticationType,
        [switch]$UseManagedClient,
        [NtCoreLib.Win32.Rpc.Transport.RpcTransportSecurity]$Security = (New-RpcTransportSecurity)
    )

    $intf = [NtCoreLib.Win32.Rpc.Management.RpcManagementInterface]::new($Binding, $UseManagedClient, $Security)
    $intf.QueryServicePrincipalName($AuthenticationType)
}

<#
.SYNOPSIS
Create a transport security object a RPC client.
.DESCRIPTION
This cmdlet creates a transport security object for a RPC client.
.PARAMETER Binding
Specify the server binding.
.PARAMETER AuthenticationType
Specify the authentication type.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Rpc.Transport.RpcTransportSecurity
#>
function New-RpcTransportSecurity {
    Param(
        [NtCoreLib.Security.Token.SecurityQualityOfService]$SecurityQualityOfService,
        [NtCoreLib.Win32.Security.Authentication.AuthenticationCredentials]$Credentials,
        [string]$ServicePrincipalName,
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationLevel]$AuthenticationLevel = "None",
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationType]$AuthenticationType = "None",
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationCapabilities]$AuthenticationCapabilities = "None"
    )

    $security = New-Object NtCoreLib.Win32.Rpc.Transport.RpcTransportSecurity
    $security.SecurityQualityOfService = $SecurityQualityOfService
    $security.Credentials = $Credentials
    $security.ServicePrincipalName = $ServicePrincipalName
    $security.AuthenticationLevel = $AuthenticationLevel
    $security.AuthenticationType = $AuthenticationType
    $security.AuthenticationCapabilities = $AuthenticationCapabilities
    $security
}

<#
.SYNOPSIS
Get the listening interfaces for a RPC server.
.DESCRIPTION
This cmdlet gets the listening interfaces for a RPC server.
.PARAMETER Binding
Specify the server binding.
.PARAMETER UseManagedClient
Specify to use a managed client.
.PARAMETER Security
Specify security to use with a managed client.
.INPUTS
None
.OUTPUTS
NtCoreLib.Ndr.Rpc.RpcSyntaxIdentifier
#>
function Get-RpcInterface {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Rpc.EndpointMapper.RpcStringBinding]$Binding,
        [switch]$UseManagedClient,
        [NtCoreLib.Win32.Rpc.Transport.RpcTransportSecurity]$Security = (New-RpcTransportSecurity)
    )

    $intf = [NtCoreLib.Win32.Rpc.Management.RpcManagementInterface]::new($Binding, $UseManagedClient, $Security)
    $intf.QueryInterfaces() | Write-Output
}

<#
.SYNOPSIS
Create a configuration a RPC client transport.
.DESCRIPTION
This cmdlet creates a new configuration for and RPC client transport.
.PARAMETER Binding
Specify the string binding.
.PARAMETER ProtocolSequence
Specify the protocol sequence.
.PARAMETER Endpoint
Specify the endpoint.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Rpc.Transport.RpcClientTransportConfiguration
#>
function New-RpcClientTransportConfig {
        [CmdletBinding(DefaultParameterSetName="FromProtocol")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromProtocol")]
        [string]$ProtocolSequence,
        [parameter(Mandatory, ParameterSetName = "FromBinding")]
        [NtCoreLib.Win32.Rpc.EndpointMapper.RpcStringBinding]$Binding,
        [parameter(Mandatory, ParameterSetName = "FromEndpoint")]
        [NtCoreLib.Win32.Rpc.EndpointMapper.RpcEndpoint]$Endpoint
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromProtocol" {
            [NtCoreLib.Win32.Rpc.Transport.RpcClientTransportConfiguration]::Create($ProtocolSequence)
        }
        "FromBinding" {
            [NtCoreLib.Win32.Rpc.Transport.RpcClientTransportConfiguration]::Create($Binding)
        }
        "FromEndpoint" {
            [NtCoreLib.Win32.Rpc.Transport.RpcClientTransportConfiguration]::Create($Endpoint)
        }
    }
}

Register-ArgumentCompleter -CommandName New-RpcClientTransportConfig -ParameterName ProtocolSequence -ScriptBlock $protseq_completer

<#
.SYNOPSIS
Get the association group ID for a client.
.DESCRIPTION
This cmdlet gets the association group ID for a client.
.PARAMETER Client
Specify the RPC client.
.INPUTS
None
.OUTPUTS
int
#>
function Get-RpcClientAssociationGroupId {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Rpc.Client.RpcClientBase]$Client
    )
    if ($Client.Transport -is [NtCoreLib.Win32.Rpc.Transport.RpcConnectedClientTransport]) {
        $Client.Transport.AssociationGroupId
    } else {
        0
    }
}

<#
.SYNOPSIS
Parses COM proxy information.
.DESCRIPTION
This cmdlet parses the COM proxy information for an interface.
.PARAMETER Path
The path to the DLL containing the COM proxy information.
.PARAMETER Clsid
CLSID for the object used to find the proxy information.
.PARAMETER Iid
IID for the proy used to find the proxy information.
.OUTPUTS
NtCoreLib.Win32.Com.Proxy.ComProxyFile
#>
function Get-ComProxyFile {
    [CmdletBinding(DefaultParameterSetName="FromFile")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName="FromFile")]
        [string]$Path,
        [parameter(ParameterSetName="FromFile")]
        [parameter(Mandatory, ParameterSetName="FromClsid")]
        [Guid]$Clsid = [Guid]::Empty,
        [parameter(Mandatory, ParameterSetName="FromIid")]
        [Guid]$Iid
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromFile" {
            $Path = Resolve-Path $Path -ErrorAction Stop
            [NtCoreLib.Win32.Com.Proxy.ComProxyFile]::FromFile($Path, $Clsid)
        }
        "FromClsid" {
            [NtCoreLib.Win32.Com.Proxy.ComProxyFile]::FromClsid($Clsid)
        }
        "FromIid" {
            [NtCoreLib.Win32.Com.Proxy.ComProxyFile]::FromIid($Iid)
        }
    }
}

<#
.SYNOPSIS
Format an NDR COM proxy file.
.DESCRIPTION
This cmdlet formats a parsed COM proxy file.
.PARAMETER Proxy
The proxy to format.
.PARAMETER Format
The output text format.
.PARAMETER RemoveComments
Specify to remove comments.
.OUTPUTS
string - The formatted proxy.
.EXAMPLE
Format-ComProxyFile $proxy
Format a COM proxy.
.EXAMPLE
$proxies | Format-ComProxyFile
Format a list of COM proxies from a pipeline.
#>
function Format-ComProxyFile {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Win32.Com.Proxy.ComProxyFile]$Proxy,
        [NtCoreLib.Ndr.Formatter.NdrFormatterTextFormat]$Format = "Idl",
        [switch]$RemoveComments
    )

    PROCESS {
        $flags = 0
        if ($RemoveComments) {
            $flags = "RemoveComments"
        }
        $Proxy.FormatAsText($flags, $Format)
    }
}

<#
.SYNOPSIS
Connect to a SAM server.
.DESCRIPTION
This cmdlet connects to a SAM server for a specified system and access rights.
.PARAMETER ServerName
Specify the target system.
.PARAMETER Access
Specify the access rights on the server.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Sam.SamServer
.EXAMPLE
Connect-SamServer
Connect to the local SAM server with maximum access.
.EXAMPLE
Connect-SamServer -ServerName "PRIMARYDC"
Connect to the SAM server on the system PRIMARYDC with maximum access.
.EXAMPLE
Connect-SamServer -Access EnumerateDomains
Connect to the local SAM server with EnumerateDomains access.
#>
function Connect-SamServer { 
    [CmdletBinding()]
    param(
        [NtCoreLib.Win32.Security.Sam.SamServerAccessRights]$Access = "MaximumAllowed",
        [string]$ServerName
    )

    [NtCoreLib.Win32.Security.Sam.SamServer]::Connect($ServerName, $Access)
}

<#
.SYNOPSIS
Get a domain object from a SAM server.
.DESCRIPTION
This cmdlet opens a domain object from a SAM server. Defaults to returning all accessible domain objects.
.PARAMETER Server
The server the query for the domain.
.PARAMETER Access
Specify the access rights on the domain object.
.PARAMETER InfoOnly
Specify to only get domain information not objects.
.PARAMETER Name
Specify to get domain by name.
.PARAMETER DomainId
Specify to get domain by SID.
.PARAMETER Builtin
Specify to open the builtin domain.
.PARAMETER User
Specify to open the user domain.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Sam.SamDomain
.EXAMPLE
Get-SamDomain -Server $server
Get all accessible domain objects from the server.
.EXAMPLE
Get-SamDomain -Server $server -InfoOnly
Get all Information only domain from the server.
.EXAMPLE
Get-SamDomain -Server $server -Name "FLUBBER"
Get the FLUBBER domain object from the server.
#>
function Get-SamDomain { 
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Sam.SamServer]$Server,
        [Parameter(Mandatory, Position = 1, ParameterSetName="FromName")]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName="FromSid")]
        [NtCoreLib.Security.Authorization.Sid]$DomainId,
        [Parameter(Mandatory, ParameterSetName="FromUser")]
        [switch]$User,
        [Parameter(Mandatory, ParameterSetName="FromBuiltin")]
        [switch]$Builtin,
        [Parameter(ParameterSetName="All")]
        [Parameter(ParameterSetName="FromName")]
        [Parameter(ParameterSetName="FromSid")]
        [Parameter(ParameterSetName="FromUser")]
        [Parameter(ParameterSetName="FromBuiltin")]
        [NtCoreLib.Win32.Security.Sam.SamDomainAccessRights]$Access = "MaximumAllowed",
        [Parameter(Mandatory, ParameterSetName="AllInfoOnly")]
        [switch]$InfoOnly
    )

    if ($InfoOnly) {
        $Server.EnumerateDomains() | ForEach-Object { 
            [PSCustomObject]@{
                Name = $_.Name
                DomainId = $Server.LookupDomain($_.Name)
            }
        }
    } else {
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Server.OpenAccessibleDomains($Access) | Write-Output
            }
            "FromName" {
                $Server.OpenDomain($Name, $Access)
            }
            "FromSid" {
                $Server.OpenDomain($DomainId, $Access)
            }
            "FromBuiltin" {
                $Server.OpenBuiltinDomain($Access)
            }
            "FromUser" {
                $Server.OpenUserDomain($Access)
            }
        }
    }
}

<#
.SYNOPSIS
Get a user object from a SAM server.
.DESCRIPTION
This cmdlet opens a user object from a SAM server.
.PARAMETER Domain
Specify the domain to get the user from.
.PARAMETER Access
Specify the access rights on the user object.
.PARAMETER InfoOnly
Specify to only get user information not objects.
.PARAMETER Name
Specify to get user by name.
.PARAMETER Sid
Specify to get user by SID.
.PARAMETER UserId
Specify to get user by ID.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Sam.SamUser
.EXAMPLE
Get-SamUser -Domain $domain
Get all accessible user objects in the domain.
.EXAMPLE
Get-SamUser -Domain $domain -InfoOnly
Get all Information only users from the server.
.EXAMPLE
Get-SamUser -Domain $domain -Name "ALICE"
Get the ALICE user object from the server.
.EXAMPLE
Get-SamUser -Domain $domain -UserId 500
Get the user object from the server with the user ID of 500.
#>
function Get-SamUser { 
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Sam.SamDomain]$Domain,
        [Parameter(Mandatory, Position = 1, ParameterSetName="FromName")]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName="FromSid")]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [Parameter(Mandatory, ParameterSetName="FromUserId")]
        [uint32]$UserId,
        [Parameter(ParameterSetName="All")]
        [Parameter(ParameterSetName="FromName")]
        [Parameter(ParameterSetName="FromSid")]
        [Parameter(ParameterSetName="FromUserId")]
        [NtCoreLib.Win32.Security.Sam.SamUserAccessRights]$Access = "MaximumAllowed",
        [Parameter(ParameterSetName="All")]
        [Parameter(ParameterSetName="AllInfoOnly")]
        [NtCoreLib.Win32.Security.Sam.UserAccountControlFlags]$Flags = 0,
        [Parameter(Mandatory, ParameterSetName="AllInfoOnly")]
        [switch]$InfoOnly
    )

    if ($InfoOnly) {
        $Domain.EnumerateUsers() | ForEach-Object { 
            [PSCustomObject]@{
                Name = $_.Name
                Sid = Get-NtSid -Sddl ($Domain.LookupId($_.RelativeId).Sddl)
            }
        }
    } else {
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Domain.OpenAccessibleUsers($Flags, $Access) | Write-Output
            }
            "FromName" {
                $Domain.OpenUser($Name, $Access)
            }
            "FromSid" {
                $Domain.OpenUser($Sid, $Access)
            }
            "FromUserId" {
                $Domain.OpenUser($UserId, $Access)
            }
        }
    }
}

<#
.SYNOPSIS
Get a group object from a SAM server.
.DESCRIPTION
This cmdlet opens a group object from a SAM server.
.PARAMETER Domain
Specify the domain to get the group from.
.PARAMETER Access
Specify the access rights on the group object.
.PARAMETER InfoOnly
Specify to only get group information not objects.
.PARAMETER Name
Specify to get group by name.
.PARAMETER Sid
Specify to get group by SID.
.PARAMETER GroupId
Specify to get group by ID.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Sam.SamGroup
.EXAMPLE
Get-SamGroup -Domain $domain
Get all accessible group objects in the domain.
.EXAMPLE
Get-SamGroup -Domain $domain -InfoOnly
Get all Information only groups from the server.
.EXAMPLE
Get-SamGroup -Domain $domain -Name "USERS"
Get the USERS group object from the server.
.EXAMPLE
Get-SamGroup -Domain $domain -GroupId 501
Get the group object from the server with the group ID of 501.
#>
function Get-SamGroup { 
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Sam.SamDomain]$Domain,
        [Parameter(Mandatory, Position = 1, ParameterSetName="FromName")]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName="FromSid")]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [Parameter(Mandatory, ParameterSetName="FromId")]
        [uint32]$GroupId,
        [Parameter(ParameterSetName="All")]
        [Parameter(ParameterSetName="FromName")]
        [Parameter(ParameterSetName="FromSid")]
        [Parameter(ParameterSetName="FromId")]
        [NtCoreLib.Win32.Security.Sam.SamGroupAccessRights]$Access = "MaximumAllowed",
        [Parameter(Mandatory, ParameterSetName="AllInfoOnly")]
        [switch]$InfoOnly
    )

    if ($InfoOnly) {
        $Domain.EnumerateGroups() | ForEach-Object { 
            [PSCustomObject]@{
                Name = $_.Name
                Sid = Get-NtSid -Sddl ($Domain.LookupId($_.RelativeId).Sddl)
            }
        }
    } else {
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Domain.OpenAccessibleGroups($Access) | Write-Output
            }
            "FromName" {
                $Domain.OpenGroup($Name, $Access)
            }
            "FromSid" {
                $Domain.OpenGroup($Sid, $Access)
            }
            "FromId" {
                $Domain.OpenGroup($GroupId, $Access)
            }
        }
    }
}

<#
.SYNOPSIS
Get a membership of a group object from a SAM server.
.DESCRIPTION
This cmdlet queries the membership of a group object from a SAM server.
.PARAMETER Group
Specify the group object to get the members from.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Sam.SamGroupMember[]
.EXAMPLE
Get-SamGroupMember -Group $group
Get members of the group objects.
#>
function Get-SamGroupMember { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Sam.SamGroup]$Group
    )

    $Group.GetMembers() | Write-Output
}

<#
.SYNOPSIS
Get a membership of an alias object from a SAM server.
.DESCRIPTION
This cmdlet queries the membership of an alias object from a SAM server.
.PARAMETER Alias
Specify the alias object to get the members from.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.Sid[]
.EXAMPLE
Get-SamGroupMember -Alias $alias
Get members of the group objects.
#>
function Get-SamAliasMember { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Sam.SamAlias]$Alias
    )

    $Alias.GetMembers() | Write-Output
}

<#
.SYNOPSIS
Get an alias object from a SAM server.
.DESCRIPTION
This cmdlet opens an alias object from a SAM server.
.PARAMETER Domain
Specify the domain to get the alias from.
.PARAMETER Access
Specify the access rights on the alias object.
.PARAMETER InfoOnly
Specify to only get alias information not objects.
.PARAMETER Name
Specify to get alias by name.
.PARAMETER Sid
Specify to get alias by SID.
.PARAMETER GroupId
Specify to get alias by ID.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Sam.SamAlias
.EXAMPLE
Get-SamAlias -Domain $domain
Get all accessible alias objects in the domain.
.EXAMPLE
Get-SamAlias -Domain $domain -InfoOnly
Get all Information only aliases from the server.
.EXAMPLE
Get-SamAlias -Domain $domain -Name "RESOURCE"
Get the RESOURCE alias object from the server.
.EXAMPLE
Get-SamAlias -Domain $domain -AliasId 502
Get the alias object from the server with the alias ID of 502.
#>
function Get-SamAlias { 
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Sam.SamDomain]$Domain,
        [Parameter(Mandatory, Position = 1, ParameterSetName="FromName")]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName="FromSid")]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [Parameter(Mandatory, ParameterSetName="FromId")]
        [uint32]$AliasId,
        [Parameter(ParameterSetName="All")]
        [Parameter(ParameterSetName="FromName")]
        [Parameter(ParameterSetName="FromSid")]
        [Parameter(ParameterSetName="FromId")]
        [NtCoreLib.Win32.Security.Sam.SamAliasAccessRights]$Access = "MaximumAllowed",
        [Parameter(Mandatory, ParameterSetName="AllInfoOnly")]
        [switch]$InfoOnly
    )

    if ($InfoOnly) {
        $Domain.EnumerateAliases() | ForEach-Object { 
            [PSCustomObject]@{
                Name = $_.Name
                Sid = Get-NtSid -Sddl ($Domain.LookupId($_.RelativeId).Sddl)
            }
        }
    } else {
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Domain.OpenAccessibleAliases($Access) | Write-Output
            }
            "FromName" {
                $Domain.OpenAlias($Name, $Access)
            }
            "FromSid" {
                $Domain.OpenAlias($Sid, $Access)
            }
            "FromId" {
                $Domain.OpenAlias($AliasId, $Access)
            }
        }
    }
}

<#
.SYNOPSIS
Create a new SAM user.
.DESCRIPTION
This cmdlet creates a new SAM user.
.PARAMETER Domain
Specify the domain to create the user in.
.PARAMETER Access
Specify the access rights on the user object.
.PARAMETER Name
Specify to name of the user.
.PARAMETER AccountType
Specify the type of account to create.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Sam.SamUser
.EXAMPLE
New-SamUser -Domain $domain -Name "bob"
Create the bob user in the domain.
.EXAMPLE
New-SamUser -Domain $domain -Name "FILBERT$" -AccountType Workstation
Create the FILBERT$ computer account in the domain.
#>
function New-SamUser { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Sam.SamDomain]$Domain,
        [Parameter(Mandatory, Position = 1)]
        [string]$Name,
        [NtCoreLib.Win32.Security.Sam.SamAliasAccessRights]$Access = "MaximumAllowed",
        [NtCoreLib.Win32.Security.Sam.SamUserAccountType]$AccountType = "User"
    )
    $Domain.CreateUser($Name, $AccountType, $Access)
}

<#
.SYNOPSIS
Get IPsec security information for a socket.
.DESCRIPTION
This cmdlet gets the IPsec security information for a socket.
.PARAMETER Socket
The socket to query.
.PARAMETER Client
The TCP client to query.
.PARAMETER PeerAddress
The IP peer address for UDP sockets.
.PARAMETER Access
The token access rights to query the peer tokens.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Sockets.Security.SocketSecurityInformation
.EXAMPLE
Get-SocketSecurity -Socket $sock
Get the security information for a socket.
.EXAMPLE
Get-SocketSecurity -Socket $sock -PeerAddress $ep
Get the security information for a socket with a peer address.
.EXAMPLE
Get-SocketSecurity -Socket $sock -Access Impersonate
Get the security information for a socket and query for peer tokens with Impersonate access.
.EXAMPLE
Get-SocketSecurity -Client $client
Get the security information for a TCP client.
#>
function Get-SocketSecurity { 
    [CmdletBinding(DefaultParameterSetName="FromSocket")]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromSocket")]
        [System.Net.Sockets.Socket]$Socket,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromTcpClient")]
        [System.Net.Sockets.TcpClient]$Client,
        [Parameter(ParameterSetName="FromSocket")]
        [System.Net.IPEndPoint]$PeerAddress,
        [NtCoreLib.TokenAccessRights]$Access = 0
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromSocket" {
            [NtCoreLib.Net.Sockets.Security.SocketSecurityUtils]::QuerySecurity($Socket, $PeerAddress, $Access)
        }
        "FromTcpClient" {
            [NtCoreLib.Net.Sockets.Security.SocketSecurityUtils]::QuerySecurity($Client, $Access)
        }
    }
}

<#
.SYNOPSIS
Set IPsec security information for a socket.
.DESCRIPTION
This cmdlet sets the IPsec security information for a socket.
.PARAMETER Socket
The socket to set.
.PARAMETER Client
The TCP client to set.
.PARAMETER Listener
The TCP listener to set.
.PARAMETER Flags
The flags for the security protocol.
.PARAMETER IpsecFlags
The flags for IPsec.
.PARAMETER MMPolicyKey
The MM policy key.
.PARAMETER QMPolicyKey
The QM policy key.
.PARAMETER Credentials
The user credentials.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-SocketSecurity -Socket $sock
Set default security information for a socket.
.EXAMPLE
Get-SocketSecurity -Socket $sock -SecurityProtocol IPsec
Set the IPsec security information for a socket.
#>
function Set-SocketSecurity { 
    [CmdletBinding(DefaultParameterSetName="FromSocket")]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromSocket")]
        [System.Net.Sockets.Socket]$Socket,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromTcpClient")]
        [System.Net.Sockets.TcpClient]$Client,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromTcpListener")]
        [System.Net.Sockets.TcpListener]$Listener,
        [NtCoreLib.Net.Sockets.Security.SocketSecuritySettingFlags]$Flags = 0,
        [NtCoreLib.Net.Sockets.Security.SocketSecurityIpsecFlags]$IpsecFlags = 0,
        [guid]$MMPolicyKey = [guid]::Empty,
        [guid]$QMPolicyKey = [guid]::Empty,
        [NtCoreLib.Win32.Security.Authentication.UserCredentials]$Credentials
    )

    $setting = [NtCoreLib.Net.Sockets.Security.SocketSecuritySettings]::new()
    $setting.Flags = $Flags
    $setting.IpsecFlags = $IpsecFlags
    $setting.MMPolicyKey = $MMPolicyKey
    $setting.QMPolicyKey = $QMPolicyKey
    $setting.Credentials = $Credentials

    switch($PSCmdlet.ParameterSetName) {
        "FromSocket" {
            [NtCoreLib.Net.Sockets.Security.SocketSecurityUtils]::SetSecurity($Socket, $setting)
        }
        "FromTcpClient" {
            [NtCoreLib.Net.Sockets.Security.SocketSecurityUtils]::SetSecurity($Client, $setting)
        }
        "FromTcpListener" {
            [NtCoreLib.Net.Sockets.Security.SocketSecurityUtils]::SetSecurity($Listener, $setting)
        }
    }
}

<#
.SYNOPSIS
Set IPsec target peer for a socket.
.DESCRIPTION
This cmdlet sets the IPsec security information for a socket.
.PARAMETER Socket
The socket to set.
.PARAMETER Client
The TCP client to set.
.PARAMETER Listener
The TCP listener to set.
.PARAMETER TargetName
The peer target name to set.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-SocketPeerTargetName -Socket $sock -TargetName "SERVER"
Set peer target name for a socket.
#>
function Set-SocketPeerTargetName { 
    [CmdletBinding(DefaultParameterSetName="FromSocket")]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromSocket")]
        [System.Net.Sockets.Socket]$Socket,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromTcpClient")]
        [System.Net.Sockets.TcpClient]$Client,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromTcpListener")]
        [System.Net.Sockets.TcpListener]$Listener,
        [Parameter(Mandatory, Position = 1)]
        [string]$TargetName
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromSocket" {
            [NtCoreLib.Net.Sockets.Security.SocketSecurityUtils]::SetPeerTargetName($Socket, $TargetName)
        }
        "FromTcpClient" {
            [NtCoreLib.Net.Sockets.Security.SocketSecurityUtils]::SetPeerTargetName($Client, $TargetName)
        }
        "FromTcpListener" {
            [NtCoreLib.Net.Sockets.Security.SocketSecurityUtils]::SetPeerTargetName($Listener, $TargetName)
        }
    }
}

<#
.SYNOPSIS
Get the HyperV socket table.
.DESCRIPTION
This cmdlet gets the HyperV socket table, either for listeners or connected sockets. Must be run as an administrator.
.PARAMETER Listener
Get the list of listeners, otherwise get connected sockets.
.PARAMETER Partition
Get sockets for a specific partition.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Sockets.HyperV.HyperVSocketTableEntry[]
#>
function Get-HyperVSocketTable {
    param(
        [switch]$Listener,
        [guid]$Partition = [guid]::Empty
    )
    [NtCoreLib.Net.Sockets.HyperV.HyperVSocketUtils]::GetSocketTable($Listener, $Partition) | Write-Output
}

<#
.SYNOPSIS
Get the HyperV socket local addresses.
.DESCRIPTION
This cmdlet gets the HyperV socket local addresses. If not parameters specified then it'll return the local address.
.PARAMETER Parent
Get the parent addresss.
.PARAMETER SiloHost
Get the parent address.
.INPUTS
None
.OUTPUTS
Guid?
#>
function Get-HyperVSocketAddress {
    [CmdletBinding(DefaultParameterSetName="LocalAddress")]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="ParentAddress")]
        [switch]$Parent,
        [Parameter(Mandatory, Position = 0, ParameterSetName="SiloHostAddress")]
        [switch]$SiloHost
    )
    if ($Parent) {
        [NtCoreLib.Net.Sockets.HyperV.HyperVSocketUtils]::ParentAddress
    } elseif($SiloHost) {
        [NtCoreLib.Net.Sockets.HyperV.HyperVSocketUtils]::SiloHostAddress
    } else {
        [NtCoreLib.Net.Sockets.HyperV.HyperVSocketUtils]::LocalAddress
    }
}

function Format-ObjectTable {
    Param(
        [parameter(Mandatory, Position = 0)]
        $InputObject,
        [switch]$HideTableHeaders,
        [switch]$NoTrailingLine
    )

    $output = $InputObject | Format-Table -HideTableHeaders:$HideTableHeaders | Out-String
    $output -Split "`r`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Write-Output
    if (!$NoTrailingLine) {
        Write-Output ""
    }
}

<#
.SYNOPSIS
Get API set entries
.DESCRIPTION
This cmdlet gets API set entries for the current system.
.PARAMETER Name
Specify an API set name to lookup.
.INPUTS
None
.OUTPUTS
NtCoreLib.Image.ApiSet.ApiSetEntry[]
.EXAMPLE
Get-NtApiSet
Get all API set entries.
.EXAMPLE
Get-NtApiSet -Name "api-ms-win-base-util-l1-1-0"
Get an API set by name.
#>
function Get-NtApiSet {
    [CmdletBinding(DefaultParameterSetName="All")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName="FromName")]
        [string]$Name
    )

    if ($PSCmdlet.ParameterSetName -eq "FromName") {
        [NtCoreLib.Image.ApiSet.ApiSetNamespace]::Current.GetApiSet($Name)
    } else {
        [NtCoreLib.Image.ApiSet.ApiSetNamespace]::Current.Entries | Write-Output
    }
}

<#
.SYNOPSIS
Get the SDK name for an enumerated type or other type.
.DESCRIPTION
This cmdlet removes a package SID from the list of granted loopback exceptions.
.PARAMETER InputObject
The package SID to remove.
.INPUTS
object
.OUTPUTS
string
.EXAMPLE
Get-NtAccessMask 0x1 -AsSpecificAccess File | Get-NtSDKName
Get the SDK names for an access mask.
#>
function Get-NtSDKName { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        $InputObject
    )
    PROCESS {
        [NtCoreLib.Utilities.Reflection.ReflectionUtils]::GetSDKName($InputObject)
    }
}

<#
.SYNOPSIS
Converts a text hexdump into bytes.
.DESCRIPTION
This cmdlet tries to convert a hexdump into the original bytes.
.PARAMETER Hex
The hex dump.
.INPUTS
string
.OUTPUTS
byte[]
.EXAMPLE
1, 2, 3, 4 | Format-HexDump | ConvertFrom-HexDump
Convert some bytes to a hex dump and back again.
#>
function ConvertFrom-HexDump { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [string]$Hex
    )

    PROCESS {
        [NtCoreLib.Utilities.Text.HexDumpBuilder]::ParseHexDump($Hex)
    }
}

<#
.SYNOPSIS
Gets a certificate object.
.DESCRIPTION
This cmdlet gets a certificate object from a path.
.PARAMETER Path
Specify the path to the certificate or file. Can only be a cert:\ drive path.
.PARAMETER Pin
Specify the PIN for the certificate's private key if needed.
.PARAMETER Byte
Specify the certificate as bytes.
.INPUTS
None
.OUTPUTS
System.Security.Cryptography.X509Certificates.X509Certificate2
#>
function Get-X509Certificate {
    [CmdletBinding(DefaultParameterSetName="FromPath")]
    param(
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromPath")]
        [string]$Path,
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromByte")]
        [byte[]]$Byte,
        [NtObjectManager.Utils.PasswordHolder]$Pin
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromPath" {
            $Path = Resolve-Path -Path $Path
            if ($null -ne $Path) {
                $cert = Get-Item $Path
                if ($cert -is [Security.Cryptography.X509Certificates.X509Certificate]) {
                    [Security.Cryptography.X509Certificates.X509Certificate2]::new($cert)
                } elseif ($Pin -eq $null) {
                    [Security.Cryptography.X509Certificates.X509Certificate2]::new($Path)
                } else {
                    [Security.Cryptography.X509Certificates.X509Certificate2]::new($Path, $Pin.Password)
                }
            }
        }
        "FromByte" {
            if ($Pin -eq $null) {
                [Security.Cryptography.X509Certificates.X509Certificate2]::new($Byte)
            } else {
                [Security.Cryptography.X509Certificates.X509Certificate2]::new($Byte, $Pin.Password)
            }
        }
    }
}

<#
.SYNOPSIS
Waits on an async task and gets the result.
.DESCRIPTION
This cmdlet waits on a .net asynchronous task and returns any result.
.PARAMETER Task
Specify the asynchronous task to wait on.
.PARAMETER TimeoutSec
Specify the timeout in seconds to wait for.
.INPUTS
None
.OUTPUTS
object
.EXAMPLE
Wait-AsyncTaskResult -Task $task
Wait on the task and result.
.EXAMPLE
Wait-AsyncTaskResult -Task $task -TimeoutSec 10
Wait on the task and result for up to 10 seconds.
#>
function Wait-AsyncTaskResult {
    Param(
        [parameter(Mandatory, Position = 0)]
        [System.Threading.Tasks.Task]$Task,
        [int]$TimeoutSec = [int]::MaxValue
    )

    while (-not $Task.Wait(1000)) {
        $TimeoutSec--
        if ($TimeoutSec -le 0) {
            return
        }
    }

    $Task.GetAwaiter().GetResult() | Write-Output
}

<#
.SYNOPSIS
Formats a hex dump for a byte array.
.DESCRIPTION
This cmdlet converts a byte array to a hex dump string. If invoked as Out-HexDump will write the to the console.
.PARAMETER Bytes
The bytes to convert.
.PARAMETER ShowHeader
Display a header for the hex dump.
.PARAMETER ShowAddress
Display the address for the hex dump.
.PARAMETER ShowAscii
Display the ASCII dump along with the hex.
.PARAMETER HideRepeating
Hide repeating 16 byte patterns.
.PARAMETER Buffer
Show the contents of a safe buffer.
.PARAMETER Offset
Specify start offset into the safe buffer or the file.
.PARAMETER Length
Specify length of safe buffer or the file.
.PARAMETER BaseAddress
Specify base address for the display when ShowAddress is enabled.
.INPUTS
byte[]
.OUTPUTS
String
#>
function Format-HexDump {
    [CmdletBinding(DefaultParameterSetName = "FromBytes")]
    Param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ParameterSetName = "FromBytes")]
        [Alias("Bytes")]
        [AllowEmptyCollection()]
        [byte[]]$Byte,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromFile")]
        [string]$Path,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromBuffer")]
        [System.Runtime.InteropServices.SafeBuffer]$Buffer,
        [Parameter(ParameterSetName = "FromBuffer")]
        [Parameter(ParameterSetName = "FromFile")]
        [int64]$Offset = 0,
        [Parameter(ParameterSetName = "FromBuffer")]
        [Parameter(ParameterSetName = "FromFile")]
        [int64]$Length = 0,
        [Parameter(ParameterSetName = "FromBytes")]
        [int64]$BaseAddress = 0,
        [switch]$ShowHeader,
        [switch]$ShowAddress,
        [switch]$ShowAscii,
        [switch]$ShowAll,
        [switch]$HideRepeating
    )

    BEGIN {
        if ($ShowAll) {
            $ShowHeader = $true
            $ShowAscii = $true
            $ShowAddress = $true
        }

        $WriteToHost = $PSCmdlet.MyInvocation.InvocationName -eq "Out-HexDump"

        switch ($PSCmdlet.ParameterSetName) {
            "FromBytes" {
                $builder = [NtCoreLib.Utilities.Text.HexDumpBuilder]::new($ShowHeader, $ShowAddress, $ShowAscii, $HideRepeating, $BaseAddress);
            }
            "FromBuffer" {
                $builder = [NtCoreLib.Utilities.Text.HexDumpBuilder]::new($Buffer, $Offset, $Length, $ShowHeader, $ShowAddress, $ShowAscii, $HideRepeating);
            }
            "FromFile" {
                $builder = [NtCoreLib.Utilities.Text.HexDumpBuilder]::new($ShowHeader, $ShowAddress, $ShowAscii, $HideRepeating, $Offset);
            }
        }
    }

    PROCESS {
        switch ($PSCmdlet.ParameterSetName) {
            "FromBytes" {
                $builder.Append($Byte)
            }
            "FromFile" {
                $Path = Resolve-Path $Path -ErrorAction Stop
                $builder.AppendFile($Path, $Offset, $Length)
            }
        }
    }

    END {
        $builder.Complete()
        $output = $builder.ToString()
        if ($WriteToHost) {
            $output | Write-Host
        } else {
            $output | Write-Output
        }
    }
}

Set-Alias -Name Out-HexDump -Value Format-HexDump

<#
.SYNOPSIS
Get a service principal name.
.DESCRIPTION
This cmdlet gets SPN for a string.
.PARAMETER Name
Specify the SPN.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.ServicePrincipalName
.EXAMPLE
Get-ServicePrincipalName -Name "HTTP/www.domain.com"
Get the SPN from a string.
#>
function Get-ServicePrincipalName {
    param (
        [parameter(Mandatory, Position = 0)]
        [string]$Name
    )
    [NtCoreLib.Win32.Security.Authentication.ServicePrincipalName]::Parse($Name) | Write-Output
}

<#
.SYNOPSIS
Get a MD4 hash of a byte array or string.
.DESCRIPTION
This cmdlet calculates the MD4 hash of a byte array or string.
.PARAMETER Bytes
Specify a byte array.
.PARAMETER String
Specify string.
.PARAMETER Encoding
Specify string encoding. Default to Unicode.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
Get-MD4Hash -String "ABC"
Get the MD4 hash of the string ABC in unicode.
.EXAMPLE
Get-MD4Hash -String "ABC" -Encoding "ASCII"
Get the MD4 hash of the string ABC in ASCII.
.EXAMPLE
Get-MD4Hash -Bytes @(0, 1, 2, 3)
Get the MD4 hash of a byte array.
#>
function Get-MD4Hash {
    [CmdletBinding(DefaultParameterSetName="FromString")]
    Param(
        [AllowEmptyString()]
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromString")]
        [string]$String,
        [Parameter(Position = 1, ParameterSetName="FromString")]
        [string]$Encoding = "Unicode",
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromBytes")]
        [byte[]]$Bytes
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromString" {
            $enc = [System.Text.Encoding]::GetEncoding($Encoding)
            [NtCoreLib.Utilities.Security.Cryptography.MD4]::CalculateHash($String, $enc)
        }
        "FromBytes" {
            [NtCoreLib.Utilities.Security.Cryptography.MD4]::CalculateHash($Bytes)
        }
    }
}

<#
.SYNOPSIS
Formats ASN.1 DER data to a string.
.DESCRIPTION
This cmdlet formats ASN.1 DER data to a string either from a byte array or a file.
.PARAMETER Byte
Specify a byte array containing the DER data.
.PARAMETER Path
Specify file containing the DER data.
.PARAMETER Depth
Specify initialize indentation depth.
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Format-ASN1DER -Byte $ba
Format the byte array with ASN.1 DER data.
.EXAMPLE
Format-ASN1DER -Byte $ba -Depth 2
Format the byte array with ASN.1 DER data with indentation depth of 2.
.EXAMPLE
Format-ASN1DER -Path file.bin
Format the file containing ASN.1 DER data.
#>
function Format-ASN1DER {
    [CmdletBinding(DefaultParameterSetName="FromBytes")]
    Param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromPath")]
        [string]$Path,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromBytes")]
        [byte[]]$Byte,
        [int]$Depth = 0
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromPath" {
            [NtCoreLib.Utilities.ASN1.ASN1Utils]::FormatDER($Path, $Depth)
        }
        "FromBytes" {
            [NtCoreLib.Utilities.ASN1.ASN1Utils]::FormatDER($Byte, $Depth)
        }
    }
}

<#
.SYNOPSIS
Parses ASN.1 DER data to objects.
.DESCRIPTION
This cmdlet parses ASN.1 DER data into an object model.
.PARAMETER Byte
Specify a byte array containing the DER data.
.PARAMETER Path
Specify file containing the DER data.
.INPUTS
None
.OUTPUTS
NtCoreLib.Utilities.ASN1.Parser.ASN1Object
.EXAMPLE
Get-ASN1DER -Bytes $ba
Parse the byte array into ASN.1 DER data objects.
#>
function Get-ASN1DER {
    [CmdletBinding(DefaultParameterSetName="FromBytes")]
    Param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromPath")]
        [string]$Path,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromBytes")]
        [byte[]]$Byte,
        [int]$Depth = 0
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromPath" {
            [NtCoreLib.Utilities.ASN1.ASN1Utils]::ParseDER($Path)
        }
        "FromBytes" {
            [NtCoreLib.Utilities.ASN1.ASN1Utils]::ParseDER($Byte)
        }
    }
}

<#
.SYNOPSIS
Creates a new ASN.1 DER builder.
.DESCRIPTION
This cmdlet creates a new ASN.1 DER builder object which can be used to create DER encoded data.
.INPUTS
None
.OUTPUTS
NtCoreLib.Utilities.ASN1.Builder.DERBuilder
.EXAMPLE
New-ASN1DER
Creates a new ASN.1 DER builder.
#>
function New-ASN1DER {
    [NtCoreLib.Utilities.ASN1.Builder.DERBuilder]::new()
}

<#
.SYNOPSIS
Split a command line into its component parts.
.DESCRIPTION
This cmdlet take a process command line and split it into its component parts.
.PARAMETER CommandLine
The command line.
.INPUTS
None
.OUTPUTS
string[]
.EXAMPLE
Split-Win32CommandLine -CommandLine "notepad test.txt"
Split the command line "notepad test.txt"
#>
function Split-Win32CommandLine {
    Param(
        [parameter(Position = 0, Mandatory)]
        [string]$CommandLine
    )
    [NtCoreLib.Win32.Process.Win32ProcessUtils]::ParseCommandLine($CommandLine) | Write-Output
}

# We use this incase we're running on a downlevel PowerShell.
function Get-IsPSCore {
    return ($PSVersionTable.Keys -contains "PSEdition") -and ($PSVersionTable.PSEdition -ne 'Desktop')
}

<#
.SYNOPSIS
Protect a byte array using RC4.
.DESCRIPTION
This cmdlet used the RC4 encryption algorithm to protect a byte array. Note as encryption
and decryption are symmetrical this function process encrypts and decrypts. Note this 
returns the encrypted data, it doesn't encrypt place.
.PARAMETER Data
The bytes to encrypt.
.PARAMETER Key
The key to use.
.PARAMETER Offset
The offset into the data to unprotect. Defaults to the start of the data.
.PARAMETER Length
The length of the data to unprotect. Defaults to all remaining data.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
Protect-RC4 -Byte @(0, 1, 2, 3) -Key @(4, 7, 1, 254)
Protect the byte array with RC4.
#>
function Protect-RC4 {
    Param(
        [Parameter(Mandatory, Position = 0)]
        [byte[]]$Data,
        [Parameter(Mandatory, Position = 1)]
        [byte[]]$Key,
        [int]$Offset = 0,
        [int]$Length = -1
    )

    if ($Length -lt 0) {
        $Length = $Data.Length - $Offset
    }
    [NtCoreLib.Utilities.Security.Cryptography.ARC4]::Transform($Data, $Offset, $Length, $Key)
}

Set-Alias -Name Unprotect-RC4 -Value Protect-RC4

<#
.SYNOPSIS
Selects strings out a binary value.
.DESCRIPTION
This cmdlet searches through a byte buffer for ASCII or Unicode strings.
.PARAMETER Bytes
Show the strings in a bytes.
.PARAMETER Buffer
Show the strings in a safe buffer.
.PARAMETER Path
Show the strings in a file.
.PARAMETER MinimumLength
Specify the minimum string length to return.
.PARAMETER Type
Specify the types of string to return. Defaults to ASCII and Unicode.
.INPUTS
byte[]
.OUTPUTS
NtCoreLib.Utilities.Text.ExtractedString
#>
function Select-BinaryString {
    [CmdletBinding(DefaultParameterSetName = "FromBytes")]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ParameterSetName = "FromBytes")]
        [Alias("Bytes")]
        [AllowEmptyCollection()]
        [byte[]]$Byte,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromFile")]
        [string]$Path,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromBuffer")]
        [System.Runtime.InteropServices.SafeBuffer]$Buffer,
        [NtCoreLib.Utilities.Text.ExtractedStringType]$Type = "Ascii, Unicode",
        [int]$MinimumLength = 3
    )

    BEGIN {
        $stm = [System.IO.MemoryStream]::new()
        $in_pipeline = $PSCmdlet.MyInvocation.PipelinePosition -eq 1
    }

    PROCESS {
        switch ($PSCmdlet.ParameterSetName) {
            "FromBytes" {
                if ($in_pipeline) {
                    $stm.Write($Byte, 0, $Byte.Length)
                } else {
                    [NtCoreLib.Utilities.Text.StringExtractor]::Extract($Byte, $MinimumLength, $Type) | Write-Output
                }
            }
            "FromBuffer" {
                [NtCoreLib.Utilities.Text.StringExtractor]::Extract($Buffer, $MinimumLength, $Type) | Write-Output
            }
            "FromFile" {
                $Path = Resolve-Path $Path -ErrorAction Stop
                [NtCoreLib.Utilities.Text.StringExtractor]::Extract($Path, $MinimumLength, $Type) | Write-Output
            }
        }
    }

    END {
        if ($stm.Length -gt 0) {
            $stm.Position = 0
            [NtCoreLib.Utilities.Text.StringExtractor]::Extract($stm, $MinimumLength, $Type) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Send a message to update the environment from the registry.
.DESCRIPTION
This cmdlet sends the WM_SETTINGCHANGE broadcast message to force explorer (and anyone else listenting)
to update their environment variables from the registry.
.INPUTS
None
.OUTPUTS
None
#>
function Update-Win32Environment {
    $str = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("Environment")
    try {
        [NtCoreLib.NtWindow]::Broadcast.SendMessage(0x1A, [System.IntPtr]::Zero, $str) | Out-Null
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($str)
    }
}

function Read-BinaryFile {
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Path
    )
    $ba = if (Get-IsPSCore) {
        Get-Content -Path $Path -AsByteStream
    } else {
        Get-Content -Path $Path -Encoding Byte
    }
    [byte[]]$ba
}

function Write-BinaryFile {
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Path,
        [Parameter(Mandatory, Position = 1)]
        [byte[]]$Byte
    )
    if (Get-IsPSCore) {
        $Byte | Set-Content -Path $Path -AsByteStream
    } else {
        $Byte | Set-Content -Path $Path -Encoding Byte
    }
}

$native_dir = if ([System.Environment]::OSVersion.Platform -eq 'Win32NT') {
    switch([NtCoreLib.NtSystemInfo]::ProcessorInformation.ProcessorArchitecture) {
        "AMD64" { 
            "$PSScriptRoot\x64"
        }
        "Intel" {
            "$PSScriptRoot\x86"
        }
        "ARM64" {
            "$PSScriptRoot\ARM64"
        }
        "ARM" {
            "$PSScriptRoot\ARM"
        }
        default {
            ""
        }
    }
} else {
    ""
}

if ("" -ne $native_dir -and (Test-Path "$native_dir\dbghelp.dll")) {
    [NtCoreLib.Win32.Debugger.Symbols.SymbolResolver]::DefaultDbgHelpPath = "$native_dir\dbghelp.dll"
}

<#
.SYNOPSIS
Creates a symbol resolver for a process.
.DESCRIPTION
This cmdlet creates a new symbol resolver for the given process.
.PARAMETER Process
The process to create the symbol resolver on. If not specified then the current process is used.
.PARAMETER DbgHelpPath
Specify path to a dbghelp DLL to use for symbol resolving. This should be ideally the dbghelp from debugging tool for Windows
which will allow symbol servers however you can use the system version if you just want to pull symbols locally.
.PARAMETER SymbolPath
Specify path for the symbols. If not specified it will first use the _NT_SYMBOL_PATH environment variable then use the
default of 'srv*https://msdl.microsoft.com/download/symbols'
.PARAMETER Flags
Flags for the symbol resolver.
.PARAMETER TraceWriter
Specify the output text writer for symbol tracing when enabled by the flags.
.OUTPUTS
NtCoreLib.Win32.Debugger.Symbols.ISymbolResolver - The symbol resolver. Dispose after use.
.EXAMPLE
New-SymbolResolver
Get a symbol resolver for the current process with default settings.
.EXAMPLE
New-SymbolResolver -SymbolPath "c:\symbols"
Get a symbol resolver specifying for the current process specifying symbols in c:\symbols.
.EXAMPLE
New-SymbolResolver -Process $p -DbgHelpPath "c:\path\to\dbghelp.dll" -SymbolPath "srv*c:\symbols*https://blah.com/symbols"
Get a symbol resolver specifying a dbghelp path and symbol path and a specific process.
#>
function New-SymbolResolver {
    Param(
        [NtCoreLib.NtProcess]$Process,
        [string]$DbgHelpPath,
        [string]$SymbolPath,
        [NtCoreLib.Win32.Debugger.Symbols.SymbolResolverFlags]$Flags = 0,
        [System.IO.TextWriter]$TraceWriter
    )
    if ($null -eq $Process) {
        $Process = Get-NtProcess -Current
    }
    [NtCoreLib.Win32.Debugger.Symbols.SymbolResolver]::Create($Process, $DbgHelpPath, $SymbolPath, $Flags, $TraceWriter)
}

<#
.SYNOPSIS
Sets the global symbol resolver paths.
.DESCRIPTION
This cmdlet sets the global symbol resolver paths. This allows you to specify symbol resolver paths for cmdlets which support it.
.PARAMETER DbgHelpPath
Specify path to a dbghelp DLL to use for symbol resolving. This should be ideally the dbghelp from debugging tool for Windows
which will allow symbol servers however you can use the system version if you just want to pull symbols locally.
.PARAMETER SymbolPath
Specify path for the symbols.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-GlobalSymbolResolver -DbgHelpPath c:\windbg\x64\dbghelp.dll
Specify the global dbghelp path.
.EXAMPLE
Set-GlobalSymbolResolver -DbgHelpPath dbghelp.dll -SymbolPath "c:\symbols"
Specify the global dbghelp path using c:\symbols to source the symbol files.
#>
function Set-GlobalSymbolResolver {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$DbgHelpPath,
        [parameter(Position = 1)]
        [string]$SymbolPath
    )

    [NtCoreLib.Win32.Debugger.Symbols.SymbolResolver]::DefaultDbgHelpPath = $DbgHelpPath
    if ("" -ne $SymbolPath) {
        [NtCoreLib.Win32.Debugger.Symbols.SymbolResolver]::DefaultSymbolPath = $SymbolPath
    }
}

<#
.SYNOPSIS
Start a Win32 debug console.
.DESCRIPTION
This cmdlet starts a Win32 debug console and prints the debug output to the shell.
.PARAMETER Global
Capture debug output for session 0.
.PARAMETER Variable
The name of a variable to put the read debug events into.
.INPUTS
None
.OUTPUTS
None
#>
function Start-Win32DebugConsole {
    param(
        [switch]$Global,
        [string]$Variable
    )

    $res = @()
    try {
        Use-NtObject($console = New-Win32DebugConsole -Global:$Global) {
            $psvar = if ("" -ne $Variable) {
                Set-Variable -Name $Variable -Value @() -Scope global
                Get-Variable -Name $Variable
            }
            while($true) {
                $result = Read-Win32DebugConsole -Console $console -TimeoutMs 1000
                if ($null -ne $result.Output) {
                    if ($null -ne $psvar) {
                        $psvar.Value += @($result)
                    }
                    Write-Host "[$($result.ProcessId)] - $($result.Output.Trim())"
                }
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Create a new Win32 debug console.
.DESCRIPTION
This cmdlet creates Win32 debug console. You can then read debug events using Read-Win32DebugConsole.
.PARAMETER Global
Capture debug output for session 0.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Debugger.Win32DebugConsole
#>
function New-Win32DebugConsole {
    param(
        [switch]$Global
    )

    $session_id = if ($Global) {
        0
    } else {
        (Get-NtProcess -Current).SessionId
    }
    [NtCoreLib.Win32.Debugger.Win32DebugConsole]::Create($session_id)
}

<#
.SYNOPSIS
Reads a debug event from the Win32 debug console.
.DESCRIPTION
This cmdlet reads a Win32 debug event from a console.
.PARAMETER Console
The console to read from.
.PARAMETER TimeoutMs
The timeout to read in milliseconds. The default is to wait indefinitely.
.PARAMETER Async
Read the string asynchronously.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Debugger.Win32DebugString
System.Threading.Tasks.Task[Win32DebugString]
#>
function Read-Win32DebugConsole {
    param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Debugger.Win32DebugConsole]$Console,
        [int]$TimeoutMs = -1,
        [switch]$Async
    )

    if ($Async) {
        $Console.ReadAsync($TimeoutMs)
    } else {
        $Console.Read($TimeoutMs)
    }
}

<#
.SYNOPSIS
Gets the executable manifests for a PE file.
.DESCRIPTION
This cmdlet extracts the manifests from a PE file and extracts basic information such as UIAccess
setting or Auto Elevation.
.PARAMETER Path
Filename to get the executable manifest from.
.INPUTS
List of filenames
.OUTPUTS
NtCoreLib.Win32.SideBySide.ManifestFile
.EXAMPLE
Get-Win32ModuleManifest abc.dll
Gets manifest from file abc.dll.
.EXAMPLE
Get-ChildItem $env:windir\*.exe -Recurse | Get-Win32ModuleManifest
Gets all manifests from EXE files, recursively under Windows.
.EXAMPLE
Get-ChildItem $env:windir\*.exe -Recurse | Get-Win32ModuleManifest | Where-Object AutoElevate | Select-Object FullPath
Get the full path of all executables with Auto Elevate manifest configuration.
#>
function Get-Win32ModuleManifest {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [string]$Path
    )
    PROCESS {
        $fullpath = if (Test-Path $Path) {
            Resolve-Path -LiteralPath $Path
        } else {
            $Path
        }
        [NtCoreLib.Win32.SideBySide.ManifestFile]::FromExecutableFile($fullpath) | Write-Output
    }
}

<#
.SYNOPSIS
Loads a DLL into memory.
.DESCRIPTION
This cmdlet loads a DLL into memory with specified flags.
.PARAMETER Path
Specify the path to the DLL.
.PARAMETER Flags
Specify the flags for loading.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Loader.SafeLoadLibraryHandle
#>
function Import-Win32Module {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Path,
        [Parameter(Position = 1)]
        [NtCoreLib.Win32.Loader.LoadLibraryFlags]$Flags = 0
    )

    if (Test-Path $Path) {
        $Path = Resolve-Path $Path
    }

    [NtCoreLib.Win32.Loader.SafeLoadLibraryHandle]::LoadLibrary($Path, $Flags) | Write-Output
}

<#
.SYNOPSIS
Gets an existing DLL from memory.
.DESCRIPTION
This cmdlet finds an existing DLL from memory.
.PARAMETER Path
Specify the path to the DLL.
.PARAMETER Address
Specify the address of the module.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Loader.SafeLoadLibraryHandle
#>
function Get-Win32Module {
    [CmdletBinding(DefaultParameterSetName = "FromPath")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromPath")]
        [string]$Path,
        [Parameter(Mandatory, ParameterSetName = "FromAddress")]
        [IntPtr]$Address
    )

    if ($PSCmdlet.ParameterSetName -eq "FromPath") {
        if (Test-Path $Path) {
            $Path = Resolve-Path $Path
        }
        [NtCoreLib.Win32.Loader.SafeLoadLibraryHandle]::GetModuleHandle($Path) | Write-Output
    }
    else {
        [NtCoreLib.Win32.Loader.SafeLoadLibraryHandle]::GetModuleHandle($Address) | Write-Output
    }
}

<#
.SYNOPSIS
Gets the exports from a loaded DLL.
.DESCRIPTION
This cmdlet gets the list of exports from a loaded DLL or a single exported function.
.PARAMETER Module
Specify the DLL.
.PARAMETER Path
Specify the path to the DLL.
.PARAMETER ProcAddress
Specify the name of the function to query.
.INPUTS
None
.OUTPUTS
NtCoreLib.Image.DllExport[] or int64.
#>
function Get-Win32ModuleExport {
    [CmdletBinding(DefaultParameterSetName = "FromModule")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromModule")]
        [NtCoreLib.Win32.Loader.SafeLoadLibraryHandle]$Module,
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromPath")]
        [string]$Path,
        [string]$ProcAddress = ""
    )

    if ($PsCmdlet.ParameterSetName -eq "FromPath") {
        Use-NtObject($lib = Import-Win32Module -Path $Path -Flags AsDataFile) {
            if ($null -ne $lib) {
                Get-Win32ModuleExport -Module $lib -ProcAddress $ProcAddress
            }
        }
    }
    else {
        if ($ProcAddress -eq "") {
            $Module.Exports | Write-Output
        }
        else {
            $Module.GetProcAddress($ProcAddress, $true).Result.ToInt64() | Write-Output
        }
    }
}

<#
.SYNOPSIS
Gets the imports from a loaded DLL.
.DESCRIPTION
This cmdlet gets the list of imports from a loaded DLL.
.PARAMETER Module
Specify the DLL.
.PARAMETER Path
Specify the path to the DLL.
.PARAMETER DllName
Specify a name of a DLL to only show imports from.
.PARAMETER ResolveApiSet
Specify to resolve API set names to the DLl names.
.INPUTS
None
.OUTPUTS
NtCoreLib.Image.DllImport[]
#>
function Get-Win32ModuleImport {
    [CmdletBinding(DefaultParameterSetName = "FromModule")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromModule")]
        [NtCoreLib.Win32.Loader.SafeLoadLibraryHandle]$Module,
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromPath")]
        [string]$Path,
        [string]$DllName,
        [switch]$ResolveApiSet
    )

    $imports = if ($PsCmdlet.ParameterSetName -eq "FromPath") {
        Use-NtObject($lib = Import-Win32Module -Path $Path -Flags AsDataFile) {
            if ($null -ne $lib) {
                Get-Win32ModuleImport -Module $lib -ResolveApiSet:$ResolveApiSet
            }
        }
    }
    else {
        if ($ResolveApiSet) {
            $Module.ApiSetImports
        } else {
            $Module.Imports
        }
    }

    if ($DllName -ne "") {
        $imports | Where-Object DllName -eq $DllName | Select-Object -ExpandProperty Functions | Write-Output
    }
    else {
        $imports | Write-Output
    }
}

<#
.SYNOPSIS
Download a symbol file from a symbol server for a module.
.DESCRIPTION
This cmdlet extracts the debug information from a loaded module and downloads the symbol file from a symbol server.
.PARAMETER Module
Specify the loaded module.
.PARAMETER Path
Specify the path to the module.
.PARAMETER OutPath
Specify the output path to write the symbol file to. If you specify a directory it will use the original filename. Defaults to current directory.
.PARAMETER SymbolServerUrl
Specify the URL for the symbol server. Defaults to the Microsoft public symbol server.
.PARAMETER Mirror
Specify that the output file should be a mirror of the symbol path. Useful to create a local symbol cache.
.INPUTS
None
.OUTPUTS
None
#>
function Get-Win32ModuleSymbolFile {
    [CmdletBinding(DefaultParameterSetName = "FromModule")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromModule")]
        [NtCoreLib.Win32.Loader.SafeLoadLibraryHandle]$Module,
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromPath")]
        [string]$Path,
        [Parameter(Position = 1)]
        [string]$OutPath,
        [string]$SymbolServerUrl = "https://msdl.microsoft.com/download/symbols",
        [switch]$Mirror
    )

    if ($PsCmdlet.ParameterSetName -eq "FromPath") {
        Use-NtObject($lib = Import-Win32Module -Path $Path -Flags AsDataFile) {
            if ($null -ne $lib) {
                Get-Win32ModuleSymbolFile -Module $lib -OutPath $OutPath -SymbolServerUrl $SymbolServerUrl -Mirror:$Mirror
            }
        }
    }
    else {
        $debug_data = $Module.DebugData
        $name = $debug_data.PdbName
        if ($Mirror) {
            if (!(Test-Path -Path $OutPath -PathType Container)) {
                Write-Error "Output path must be a directory when using mirror."
                return
            }

            $OutPath = $debug_data.GetSymbolPath((Resolve-Path $OutPath))
            New-Item -Type Directory -Path (Split-Path $OutPath -Parent) -Force -ErrorAction Stop | Out-Null
        } else {
            if ("" -eq $OutPath) {
                $OutPath = $name
            } else {
                if (Test-Path -Path $OutPath -PathType Container) {
                    $OutPath = Join-Path $OutPath $name
                }
            }
        }
        $url = $debug_data.GetSymbolPath($SymbolServerUrl)
        Invoke-WebRequest -Uri $url -OutFile $OutPath -ErrorAction Stop
        Write-Verbose "Wrote symbol file to $OutPath"
    }
}

<#
.SYNOPSIS
Gets the resources from a loaded DLL.
.DESCRIPTION
This cmdlet gets the list of resources from a loaded DLL.
.PARAMETER Module
Specify the DLL.
.PARAMETER Path
Specify the path to the DLL.
.PARAMETER DontLoadResource
Specify to not load the resource data. Ignored if getting a specific type.
.PARAMETER Type
Specify the type of resource to get.
.PARAMETER Name
Specify the name of resource tot get. Must be combined with the Type.
.INPUTS
None
.OUTPUTS
NtCoreLib.Image.ImageResource
#>
function Get-Win32ModuleResource {
    [CmdletBinding(DefaultParameterSetName = "FromModule")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromModule")]
        [NtCoreLib.Win32.Loader.SafeLoadLibraryHandle]$Module,
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromPath")]
        [string]$Path,
        [switch]$DontLoadResource,
        [ValidateNotNull()]
        [System.Nullable[NtCoreLib.Image.ImageResourceType]]$Type,
        [ValidateNotNull()]
        [ValidateScript({
                if ($PSBoundParameters.Keys -contains 'Type') {
                        $true
                }
                else {
                    throw "Must specify a type when using a name."
                }
            })]
        [NtCoreLib.Image.ResourceString]$Name
    )

    try {
        $lib = if ($PSCmdlet.ParameterSetName -eq "FromPath") {
            Import-Win32Module -Path $Path -Flags AsDataFile
        } else {
            $Module.AddRef()
        }

        Use-NtObject($lib) {
            if ($null -ne $Type) {
                if ($null -ne $Name) {
                    $lib.LoadResource($Name, $Type)
                } else {
                    $lib.GetResources($Type, !$DontLoadResource) | Write-Output
                }
            } else {
                $lib.GetResources(!$DontLoadResource) | Write-Output
            }
        }
    }
    catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get the embedded signature information from a file.
.DESCRIPTION
This cmdlet gets the embedded authenticode signature information from a file. This differs
from Get-AuthenticodeSignature in that it doesn't take into account catalog signing which is
important for tracking down PP and PPL executables.
.PARAMETER FullName
The path to the file to extract the signature from.
#>
function Get-EmbeddedAuthenticodeSignature {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$FullName
    )
    PROCESS {
        $content_type = [System.Security.Cryptography.X509Certificates.X509ContentType]::Unknown
        try {
            $path = Resolve-Path $FullName
            $content_type = [System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($path)
        }
        catch {
            Write-Error $_
        }

        if ($content_type -ne "Authenticode") {
            return
        }

        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($path)
        $all_certs = [NtCoreLib.Win32.Security.Authenticode.AuthenticodeUtils]::GetCertificates($path) | Write-Output
        $ppl = $false
        $pp = $false
        $tcb = $false
        $system = $false
        $dynamic = $false
        $elam = $false
        $store = $false
        $ium = $false
        $enclave = $false

        foreach ($eku in $cert.EnhancedKeyUsageList) {
            switch ($eku.ObjectId) {
                "1.3.6.1.4.1.311.10.3.22" { $ppl = $true }
                "1.3.6.1.4.1.311.10.3.24" { $pp = $true }
                "1.3.6.1.4.1.311.10.3.23" { $tcb = $true }
                "1.3.6.1.4.1.311.10.3.6" { $system = $true }
                "1.3.6.1.4.1.311.61.4.1" { $elam = $true }
                "1.3.6.1.4.1.311.76.5.1" { $dynamic = $true }
                "1.3.6.1.4.311.76.3.1" { $store = $true }
                "1.3.6.1.4.1.311.10.3.37" { $ium = $true }
                "1.3.6.1.4.1.311.10.3.42" { $enclave = $true }
            }
        }

        $page_hash = [NtCoreLib.Win32.Security.Authenticode.AuthenticodeUtils]::ContainsPageHash($path)

        $props = @{
            Path                  = $Path;
            Certificate           = $cert;
            AllCertificates       = $all_certs;
            ProtectedProcess      = $pp;
            ProtectedProcessLight = $ppl;
            Tcb                   = $tcb;
            SystemComponent       = $system;
            DynamicCodeGeneration = $dynamic;
            Elam                  = $elam;
            Store                 = $store;
            IsolatedUserMode      = $ium;
            HasPageHash           = $page_hash;
            Enclave               = $enclave;
        }

        if ($elam) {
            $certs = [NtCoreLib.Win32.Security.Authenticode.AuthenticodeUtils]::GetElamInformation($path, $false)
            if ($certs.IsSuccess)
            {
                $props["ElamCerts"] = $certs.Result
            }
        }

        if ($ium) {
            $policy = [NtCoreLib.Win32.Security.Authenticode.ImagePolicyMetadata]::CreateFromFile($Path, $false)
            if ($policy.IsSuccess) {
                $props["TrustletPolicy"] = $policy.Result
            }
        }
        if ($ium -or $enclave) {
            $enclave = [NtCoreLib.Win32.Security.Authenticode.AuthenticodeUtils]::GetEnclaveConfiguration($path, $false)
            if ($enclave.IsSuccess) {
                $props["EnclaveConfig"] = $enclave.Result
                $props["EnclavePrimaryImage"] = $enclave.Result.PrimaryImage
                $props["Enclave"] = $true
            }
        }

        $obj = New-Object -TypeName PSObject -Prop $props
        Write-Output $obj
    }
}

<#
.SYNOPSIS
Create a new Win32 process configuration.
.DESCRIPTION
This cmdlet creates a new Win32 process configuration which you can then pass to New-Win32Process.
.PARAMETER CommandLine
The command line of the process to create.
.PARAMETER ApplicationName
Optional path to the application executable.
.PARAMETER ProcessSecurityDescriptor
Optional security descriptor for the process.
.PARAMETER ThreadSecurityDescriptor
Optional security descriptor for the initial thread.
.PARAMETER ParentProcess
Optional process to act as the parent, needs CreateProcess access to succeed.
.PARAMETER CreationFlags
Flags to affect process creation.
.PARAMETER TerminateOnDispose
Specify switch to terminate the process when the Win32Process object is disposed.
.PARAMETER Environment
Optional environment block for the new process.
.PARAMETER CurrentDirectory
Optional current directory for the new process.
.PARAMETER Desktop
Optional desktop for the new process.
.PARAMETER Title
Optional title for the new process.
.PARAMETER InheritHandles
Switch to specify whether to inherit handles into new process.
.PARAMETER InheritProcessHandle
Switch to specify whether the process handle is inheritable
.PARAMETER InheritThreadHandle
Switch to specify whether the thread handle is inheritable.
.PARAMETER MitigationOptions
Specify optional mitigation options.
.PARAMETER Win32kFilterFlags
Specify filter flags for Win32k filter
.PARAMETER Win32kFilterLevel
Specify the filter level for the Win32k filter.
.PARAMETER Token
Specify a token to start the process with.
.PARAMETER ProtectionLevel
Specify the protection level when creating a protected process.
.PARAMETER DebugObject
Specify a debug object to run the process under. You need to also specify DebugProcess or DebugOnlyThisProcess flags as well.
.PARAMETER NoTokenFallback
Specify to not fallback to using CreateProcessWithToken if CreateProcessAsUser fails.
.PARAMETER AppContainerProfile
Specify an app container profile to use.
.PARAMETER ExtendedFlags
 Specify extended creation flags.
.PARAMETER JobList
 Specify list of jobs to assign the process to.
.PARAMETER Credential
Specify user credentials for CreateProcessWithLogon.
.PARAMETER LogonFlags
Specify logon flags for CreateProcessWithLogon.
.PARAMETER ComponentFilter
Specify component filter flags.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Process.Win32ProcessConfig
#>
function New-Win32ProcessConfig {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$CommandLine,
        [string]$ApplicationName,
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$ProcessSecurityDescriptor,
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$ThreadSecurityDescriptor,
        [NtCoreLib.NtProcess]$ParentProcess,
        [NtCoreLib.Win32.Process.CreateProcessFlags]$CreationFlags = 0,
        [NtCoreLib.Win32.Process.ProcessMitigationOptions]$MitigationOptions = 0,
        [switch]$TerminateOnDispose,
        [byte[]]$Environment,
        [string]$CurrentDirectory,
        [string]$Desktop,
        [string]$Title,
        [switch]$InheritHandles,
        [switch]$InheritProcessHandle,
        [switch]$InheritThreadHandle,
        [NtCoreLib.Win32.Process.Win32kFilterFlags]$Win32kFilterFlags = 0,
        [int]$Win32kFilterLevel = 0,
        [NtCoreLib.NtToken]$Token,
        [NtCoreLib.Win32.Process.ProtectionLevel]$ProtectionLevel = "WindowsPPL",
        [NtCoreLib.NtDebug]$DebugObject,
        [switch]$NoTokenFallback,
        [NtCoreLib.Win32.AppModel.AppContainerProfile]$AppContainerProfile,
        [NtCoreLib.Win32.Process.ProcessExtendedFlags]$ExtendedFlags = 0,
        [NtCoreLib.ChildProcessMitigationFlags]$ChildProcessMitigations = 0,
        [NtCoreLib.NtJob[]]$JobList,
        [NtCoreLib.Win32.Security.Authentication.UserCredentials]$Credential,
        [NtCoreLib.Win32.Process.CreateProcessLogonFlags]$LogonFlags = 0,
        [NtCoreLib.Win32.Process.ProcessComponentFilterFlags]$ComponentFilter = 0
    )
    $config = New-Object NtCoreLib.Win32.Process.Win32ProcessConfig
    $config.CommandLine = $CommandLine
    if (-not [string]::IsNullOrEmpty($ApplicationName)) {
        $config.ApplicationName = $ApplicationName
    }
    $config.ProcessSecurityDescriptor = $ProcessSecurityDescriptor
    $config.ThreadSecurityDescriptor = $ThreadSecurityDescriptor
    $config.ParentProcess = $ParentProcess
    $config.CreationFlags = $CreationFlags
    $config.TerminateOnDispose = $TerminateOnDispose
    $config.Environment = $Environment
    if (-not [string]::IsNullOrEmpty($Desktop)) {
        $config.Desktop = $Desktop
    }
    if (-not [string]::IsNullOrEmpty($CurrentDirectory)) {
        $config.CurrentDirectory = $CurrentDirectory
    }
    if (-not [string]::IsNullOrEmpty($Title)) {
        $config.Title = $Title
    }
    $config.InheritHandles = $InheritHandles
    $config.InheritProcessHandle = $InheritProcessHandle
    $config.InheritThreadHandle = $InheritThreadHandle
    $config.MitigationOptions = $MitigationOptions
    $config.Win32kFilterFlags = $Win32kFilterFlags
    $config.Win32kFilterLevel = $Win32kFilterLevel
    $config.Token = $Token
    $config.ProtectionLevel = $ProtectionLevel
    $config.DebugObject = $DebugObject
    $config.NoTokenFallback = $NoTokenFallback
    if ($AppContainerProfile -ne $null) {
        $config.AppContainerSid = $AppContainerProfile.Sid
        $config.Capabilities.AddRange($AppContainerProfile.Capabilities)
    }
    $config.ExtendedFlags = $ExtendedFlags
    $config.ChildProcessMitigations = $ChildProcessMitigations
    if ($null -ne $JobList) {
        $config.JobList.AddRange($JobList)
    }
    $config.Credentials = $Credential
    $config.LogonFlags = $LogonFlags
    $config.ComponentFilter = $ComponentFilter
    return $config
}

<#
.SYNOPSIS
Create a new Win32 process.
.DESCRIPTION
This cmdlet creates a new Win32 process with an optional security descriptor.
.PARAMETER CommandLine
The command line of the process to create.
.PARAMETER ApplicationName
Optional path to the application executable.
.PARAMETER ProcessSecurityDescriptor
Optional security descriptor for the process.
.PARAMETER ThreadSecurityDescriptor
Optional security descriptor for the initial thread.
.PARAMETER ParentProcess
Optional process to act as the parent, needs CreateProcess access to succeed.
.PARAMETER CreationFlags
Flags to affect process creation.
.PARAMETER TerminateOnDispose
Specify switch to terminate the process when the Win32Process object is disposed.
.PARAMETER Environment
Optional environment block for the new process.
.PARAMETER CurrentDirectory
Optional current directory for the new process.
.PARAMETER Desktop
Optional desktop for the new process.
.PARAMETER Title
Optional title for the new process.
.PARAMETER InheritHandles
Switch to specify whether to inherit handles into new process.
.PARAMETER InheritProcessHandle
Switch to specify whether the process handle is inheritable
.PARAMETER InheritThreadHandle
Switch to specify whether the thread handle is inheritable.
.PARAMETER MitigationOptions
Specify optional mitigation options.
.PARAMETER ProtectionLevel
Specify the protection level when creating a protected process.
.PARAMETER DebugObject
Specify a debug object to run the process under. You need to also specify DebugProcess or DebugOnlyThisProcess flags as well.
.PARAMETER NoTokenFallback
Specify to not fallback to using CreateProcessWithLogon if CreateProcessAsUser fails.
.PARAMETER Token
Specify an explicit token to create the new process with.
.PARAMETER ExtendedFlags
 Specify extended creation flags.
.PARAMETER JobList
 Specify list of jobs to assign the process to.
.PARAMETER Config
Specify the configuration for the new process.
.PARAMETER Wait
Specify to wait for the process to exit.
.PARAMETER WaitTimeout
Specify the timeout to wait for the process to exit. Defaults to infinite.
.PARAMETER Credential
Specify user credentials for CreateProcessWithLogon.
.PARAMETER LogonFlags
Specify logon flags for CreateProcessWithLogon.
.PARAMETER ComponentFilter
Specify component filter flags.
.PARAMETER Close
Specify to close the process and thread handles and not return anything.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Process.Win32Process
#>
function New-Win32Process {
    [CmdletBinding(DefaultParameterSetName = "FromArgs")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromArgs")]
        [string]$CommandLine,
        [Parameter(ParameterSetName = "FromArgs")]
        [string]$ApplicationName,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$ProcessSecurityDescriptor,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$ThreadSecurityDescriptor,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtCoreLib.NtProcess]$ParentProcess,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtCoreLib.Win32.Process.CreateProcessFlags]$CreationFlags = 0,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtCoreLib.Win32.Process.ProcessMitigationOptions]$MitigationOptions = 0,
        [Parameter(ParameterSetName = "FromArgs")]
        [switch]$TerminateOnDispose,
        [Parameter(ParameterSetName = "FromArgs")]
        [byte[]]$Environment,
        [Parameter(ParameterSetName = "FromArgs")]
        [string]$CurrentDirectory,
        [Parameter(ParameterSetName = "FromArgs")]
        [string]$Desktop,
        [Parameter(ParameterSetName = "FromArgs")]
        [string]$Title,
        [Parameter(ParameterSetName = "FromArgs")]
        [switch]$InheritHandles,
        [Parameter(ParameterSetName = "FromArgs")]
        [switch]$InheritProcessHandle,
        [Parameter(ParameterSetName = "FromArgs")]
        [switch]$InheritThreadHandle,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtCoreLib.NtToken]$Token,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtCoreLib.Win32.Process.ProtectionLevel]$ProtectionLevel = "WindowsPPL",
        [Parameter(ParameterSetName = "FromArgs")]
        [NtCoreLib.NtDebug]$DebugObject,
        [Parameter(ParameterSetName = "FromArgs")]
        [switch]$NoTokenFallback,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtCoreLib.Win32.AppModel.AppContainerProfile]$AppContainerProfile,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtCoreLib.Win32.Process.ProcessExtendedFlags]$ExtendedFlags = 0,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtCoreLib.ChildProcessMitigationFlags]$ChildProcessMitigations = 0,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtCoreLib.NtJob[]]$JobList,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtCoreLib.Win32.Security.Authentication.UserCredentials]$Credential,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtCoreLib.Win32.Process.CreateProcessLogonFlags]$LogonFlags = 0,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtCoreLib.Win32.Process.ProcessComponentFilterFlags]$ComponentFilter = 0,
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromConfig")]
        [NtCoreLib.Win32.Process.Win32ProcessConfig]$Config,
        [switch]$Wait,
        [NtCoreLib.NtWaitTimeout]$WaitTimeout = [NtCoreLib.NtWaitTimeout]::Infinite,
        [switch]$Close
    )

    if ($null -eq $Config) {
        $Config = New-Win32ProcessConfig $CommandLine -ApplicationName $ApplicationName `
            -ProcessSecurityDescriptor $ProcessSecurityDescriptor -ThreadSecurityDescriptor $ThreadSecurityDescriptor `
            -ParentProcess $ParentProcess -CreationFlags $CreationFlags -TerminateOnDispose:$TerminateOnDispose `
            -Environment $Environment -CurrentDirectory $CurrentDirectory -Desktop $Desktop -Title $Title `
            -InheritHandles:$InheritHandles -InheritProcessHandle:$InheritProcessHandle -InheritThreadHandle:$InheritThreadHandle `
            -MitigationOptions $MitigationOptions -Token $Token -ProtectionLevel $ProtectionLevel -NoTokenFallback:$NoTokenFallback `
            -DebugObject $DebugObject -AppContainerProfile $AppContainerProfile -ExtendedFlags $ExtendedFlags `
            -ChildProcessMitigations $ChildProcessMitigations -JobList $JobList -Credential $Credential -LogonFlags $LogonFlags `
            -ComponentFilter $ComponentFilter
    }

    $p = $config.Create()
    if ($Wait) {
        $p.Process.Wait($WaitTimeout)
    }
    if ($Close) {
        $p.Dispose()
    } else {
        $p | Write-Output
    }
}

function Test-ProcessToken {
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtProcess]$Process,
        [parameter(Mandatory, Position = 1)]
        [NtCoreLib.Security.Authorization.Sid]$User,
        [NtCoreLib.Security.Token.TokenPrivilegeValue[]]$RequiredPrivilege,
        [NtCoreLib.Security.Authorization.Sid[]]$RequiredGroup
    )
    Use-NtObject($token = Get-NtToken -Primary -Process $Process -Access Query -ErrorAction SilentlyContinue) {
        if ($null -eq $token) {
            return $false
        }

        if ($token.User.Sid -ne $User) {
            return $false
        }
        $privs = $token.Privileges.Name
        foreach ($priv in $RequiredPrivilege) {
            if ($priv.ToString() -notin $privs) {
                return $false
            }
        }

        $groups = $token.Groups | Where-Object Enabled
        foreach ($group in $RequiredGroup) {
            if ($group -notin $groups.Sid) {
                return $false
            }
        }
    }
    return $true
}

<#
.SYNOPSIS
Starts a new Win32 process which is a child of a process meeting a set of criteria.
.DESCRIPTION
This cmdlet starts a new Win32 process which is a child of a process meeting a set of criteria such as user account, privileges and groups. You can use this as an admin to get a system process spawned on the current desktop.
.PARAMETER CommandLine
The command line of the process to create.
.PARAMETER CreationFlags
Flags to affect process creation.
.PARAMETER TerminateOnDispose
Specify switch to terminate the process when the Win32Process object is disposed.
.PARAMETER Desktop
Optional desktop for the new process.
.PARAMETER RequiredPrivilege
Optional list of privileges the parent process must have to create the child.
.PARAMETER RequiredGroup
Optional list of groups the parent process must have to create the child.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Process.Win32Process
.EXAMPLE
Start-Win32ChildProcess cmd.exe
Start a new child process as the system user.
.EXAMPLE
Start-Win32ChildProcess cmd.exe -User LS
Start a new child process as the local service user.
.EXAMPLE
Start-Win32ChildProcess cmd.exe -RequiredPrivilege SeAssignPrimaryTokenPrivilege
Start a new child process as the system user with SeAssignPrimaryTokenPrivilege.
.EXAMPLE
Start-Win32ChildProcess cmd.exe -RequiredGroup BA
Start a new child process as the system user with the builtin administrators group.
#>
function Start-Win32ChildProcess {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$CommandLine,
        [NtCoreLib.Security.Authorization.Sid]$User = "SY",
        [NtCoreLib.Security.Token.TokenPrivilegeValue[]]$RequiredPrivilege,
        [NtCoreLib.Security.Authorization.Sid[]]$RequiredGroup,
        [string]$Desktop = "WinSta0\Default",
        [NtCoreLib.Win32.Process.CreateProcessFlags]$CreationFlags = "NewConsole",
        [switch]$TerminateOnDispose,
        [switch]$PassThru
    )

    Set-NtTokenPrivilege SeDebugPrivilege | Out-Null

    Use-NtObject($ps = Get-NtProcess -Access QueryLimitedInformation, CreateProcess `
            -FilterScript { Test-ProcessToken $_ -User $User -RequiredPrivilege $RequiredPrivilege -RequiredGroup $RequiredGroup }) {
        $parent = $ps | Select-Object -First 1
        if ($null -eq $parent) {
            Write-Error "Couldn't find suitable process to spawn a child."
            return
        }
        New-Win32Process -CommandLine $CommandLine -Desktop $Desktop -CreationFlags $CreationFlags -ParentProcess $parent -TerminateOnDispose:$TerminateOnDispose
    }
}

<#
.SYNOPSIS
Formats an object's security descriptor as text.
.DESCRIPTION
This cmdlet formats the security descriptor to text for display in the console or piped to a file
Uses Get-Win32SecurityDescriptor API to query the SD then uses the Format-NtSecurityDescriptor to
display.
.PARAMETER Type
Specify the SE object type for the path. Defaults to File.
.PARAMETER Name
Specify the name of the object for the security descriptor.
.PARAMETER SecurityInformation
Specify what parts of the security descriptor to format.
.PARAMETER Summary
Specify to only print a shortened format removing redundant information.
.PARAMETER ShowAll
Specify to format all security descriptor information including the SACL.
.PARAMETER HideHeader
Specify to not print the security descriptor header.
.PARAMETER AsSddl
Specify to format the security descriptor as SDDL.
.PARAMETER Container
Specify to display the access mask from Container Access Rights.
.PARAMETER MapGeneric
Specify to map access masks back to generic access rights for the object type.
.PARAMETER SDKName
Specify to format the security descriptor using SDK names where available.
.PARAMETER ResolveObjectType
Specify to try and resolve the object type GUID from the local Active Directory.
.PARAMETER Domain
Specify to indicate the domain to query the object type from when resolving. Defaults to the current domain.
.OUTPUTS
None
.EXAMPLE
Format-Win32SecurityDescriptor -Name "c:\windows".
Format the security descriptor for the c:\windows folder..
.EXAMPLE
Format-Win32SecurityDescriptor -Name "c:\windows" -AsSddl
Format the security descriptor of an object as SDDL.
.EXAMPLE
Format-Win32SecurityDescriptor -Name "c:\windows" -AsSddl -SecurityInformation Dacl, Label
Format the security descriptor of an object as SDDL with only DACL and Label.
.EXAMPLE
Format-Win32SecurityDescriptor -Name "Machine\Software" -Type RegistryKey
Format the security descriptor of a registry key.
#>
function Format-Win32SecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName = "FromName")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromName", Mandatory)]
        [string]$Name,
        [NtCoreLib.Win32.Security.Authorization.SeObjectType]$Type = "File",
        [NtCoreLib.Security.Authorization.SecurityInformation]$SecurityInformation = "AllBasic",
        [switch]$Container,
        [alias("ToSddl")]
        [switch]$AsSddl,
        [switch]$Summary,
        [switch]$ShowAll,
        [switch]$HideHeader,
        [switch]$MapGeneric,
        [switch]$SDKName,
        [switch]$ResolveObjectType,
        [string]$Domain
    )

    Get-Win32SecurityDescriptor -Name $Name -SecurityInformation $SecurityInformation `
        -Type $Type | Format-NtSecurityDescriptor -SecurityInformation $SecurityInformation `
        -Container:$Container -AsSddl:$AsSddl -Summary:$Summary -ShowAll:$ShowAll -HideHeader:$HideHeader `
        -DisplayPath $Name -MapGeneric:$MapGeneric -SDKName:$SDKName -ResolveObjectType:$ResolveObjectType `
        -Domain $Domain
}

<#
.SYNOPSIS
Get credential manager credentials.
.DESCRIPTION
This cmdlet gets available credentials from the credential mananger.
.PARAMETER Filter
Specify a filter for the credential target, for example DOMAIN*.
.PARAMETER All
Specify to return all credentials.
.PARAMETER TargetName
Specify to return a specific credential.
.PARAMETER Type
Specify the type of credential.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Credential.Credential[]
.EXAMPLE
Get-Win32Credential
Get Win32 credentials.
.EXAMPLE
Get-Win32Credential -All
Get all Win32 credentials.
.EXAMPLE
Get-Win32Credential -Filter "DOMAIN*"
Get Win32 credentials with a target name matching a pattern.
#>
function Get-Win32Credential {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [Parameter(ParameterSetName = "All")]
        [string]$Filter,
        [Parameter(ParameterSetName = "All")]
        [switch]$All,
        [Parameter(ParameterSetName = "FromName", Position = 0, Mandatory)]
        [string]$TargetName,
        [Parameter(ParameterSetName = "FromName", Position = 1, Mandatory)]
        [NtCoreLib.Win32.Security.Credential.CredentialType]$Type
    )

    if ($PSCmdlet.ParameterSetName -eq "All") {
        $flags = if ($All) {
            "AllCredentials"
        } else {
            0
        }
        [NtCoreLib.Win32.Security.Credential.CredentialManager]::GetCredentials($Filter, $flags) | Write-Output
    } else {
        [NtCoreLib.Win32.Security.Credential.CredentialManager]::GetCredential($TargetName, $Type)
    }
}

<#
.SYNOPSIS
Backup credential manager credentials.
.DESCRIPTION
This cmdlet backs up a user's credential from the credential mananger. Needs SeTrustedCredmanAccessPrivilege to function.
.PARAMETER Token
Specify a token for the user to backup.
.PARAMETER Key
Specify optional key to encrypt the backup. Usually a password.
.PARAMETER KeyEncoded
Specify if the key is already encoded.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
Backup-Win32Credential $token
Backup credentials for user in token.
.EXAMPLE
Backup-Win32Credential $token -Key 65, 0, 32, 0
Backup credentials for user in token encrypting with a key.
#>
function Backup-Win32Credential {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.NtToken]$Token,
        [byte[]]$Key,
        [switch]$KeyEncoded
    )

    Enable-NtTokenPrivilege SeTrustedCredmanAccessPrivilege
    [NtCoreLib.Win32.Security.Credential.CredentialManager]::Backup($Token, $Key, $KeyEncoded)
}

<#
.SYNOPSIS
Delete a credential manager credential.
.DESCRIPTION
This cmdlet deletes a credential from the credential mananger.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-Win32Credential {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$TargetName,
        [Parameter(Position = 1, Mandatory)]
        [NtCoreLib.Win32.Security.Credential.CredentialType]$Type
    )

    [NtCoreLib.Win32.Security.Credential.CredentialManager]::DeleteCredential($TargetName, $Type)
}

<#
.SYNOPSIS
Set a credential manager credential.
.DESCRIPTION
This cmdlet sets a available credential in the credential mananger.
.PARAMETER TargetName
Specify the target name.
.PARAMETER Username
Specify the username.
.PARAMETER Password
Specify the password.
.PARAMETER Certificate
Specify the certificate.
.PARAMETER Pin
Specify the certificate's PIN.
.INPUTS
None
.OUTPUTS
None
#>
function Set-Win32Credential {
    [CmdletBinding(DefaultParameterSetName = "FromPassword")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$TargetName,
        [Parameter(ParameterSetName = "FromPassword", Position = 1, Mandatory)]
        [string]$Username,
        [Parameter(ParameterSetName = "FromPassword", Position = 2, Mandatory)]
        [string]$Password,
        [Parameter(ParameterSetName = "FromCertificate", Position = 1, Mandatory)]
        [X509Certificate]$Certificate,
        [Parameter(ParameterSetName = "FromCertificate", Position = 2)]
        [string]$Pin
    )

    $cred = switch($PSCmdlet.ParameterSetName) {
        "FromPassword" {
            [NtCoreLib.Win32.Security.Credential.Credential]::CreateFromPassword($TargetName, $Username, $Password)
        }
        "FromCertificate" {
            [NtCoreLib.Win32.Security.Credential.Credential]::CreateFromCertificate($TargetName, $Certificate, $Pin)
        }
    }
    [NtCoreLib.Win32.Security.Credential.CredentialManager]::SetCredential($cred)
}

<#
.SYNOPSIS
Protect a Win32 credential password.
.DESCRIPTION
This cmdlet protects a credential password.
.PARAMETER Password
Specify the password.
.PARAMETER AsSelf
Specify to encrypt the credentials for the current process.
.PARAMETER AllowToSystem
Specify to encrypt for the system user.
.PARAMETER Byte
Specify to protect an arbitrary byte array.
.INPUTS
None
.OUTPUTS
string
#>
function Protect-Win32Credential {
    [CmdletBinding(DefaultParameterSetName = "FromPassword")]
    Param(
        [Parameter(ParameterSetName = "FromPassword", Position = 0, Mandatory)]
        [string]$Password,
        [switch]$AsSelf,
        [switch]$AllowToSystem,
        [Parameter(ParameterSetName = "FromByte", Position = 0, Mandatory)]
        [byte[]]$Byte
    )

    $flags = [NtCoreLib.Win32.Security.Credential.CredentialProtectFlag]::None
    if ($AsSelf) {
        $flags = $flags -bor [NtCoreLib.Win32.Security.Credential.CredentialProtectFlag]::AsSelf
    }
    if ($AllowToSystem) {
        $flags = $flags -bor [NtCoreLib.Win32.Security.Credential.CredentialProtectFlag]::AllowToSystem
    }

    switch($PSCmdlet.ParameterSetName) {
        "FromPassword" {
            if ($AllowToSystem) {
                [NtCoreLib.Win32.Security.Credential.CredentialManager]::ProtectCredentialEx($flags, $Password)
            } else {
                [NtCoreLib.Win32.Security.Credential.CredentialManager]::ProtectCredential($AsSelf, $Password)
            }
        }
        "FromByte" {
            [NtCoreLib.Win32.Security.Credential.CredentialManager]::ProtectCredentialEx($flags, $Byte)
        }
    }
}

<#
.SYNOPSIS
Unprotect a Win32 credential password.
.DESCRIPTION
This cmdlet unprotects a credential password.
.PARAMETER Credential
Specify the protected credential
.PARAMETER AsSelf
Specify to decrypt the credentials for the current process.
.PARAMETER AllowToSystem
Specify to decrypt for the system user.
.PARAMETER AsByte
Specify to unprotect as a byte array.
.INPUTS
None
.OUTPUTS
string
byte[]
#>
function Unprotect-Win32Credential {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Credential,
        [switch]$AsSelf,
        [switch]$AllowToSystem,
        [switch]$AsByte
    )

    $flags = [NtCoreLib.Win32.Security.Credential.CredentialUnprotectFlag]::None
    if ($AsSelf) {
        $flags = $flags -bor [NtCoreLib.Win32.Security.Credential.CredentialUnprotectFlag]::AsSelf
    }
    if ($AllowToSystem) {
        $flags = $flags -bor [NtCoreLib.Win32.Security.Credential.CredentialUnprotectFlag]::AllowToSystem
    }

    if ($AllowToSystem -or $AsByte) {
        $ba = [NtCoreLib.Win32.Security.Credential.CredentialManager]::UnprotectCredentialEx($flags, $Credential)
        if ($AsByte) {
            $ba
        } else {
            [System.Text.Encoding]::Unicode.GetString($ba)
        }
    } else {
        [NtCoreLib.Win32.Security.Credential.CredentialManager]::UnprotectCredential($AsSelf, $Credential)
    }
}

<#
.SYNOPSIS
Create a new Win32 service.
.DESCRIPTION
This cmdlet creates a new Win32 service. This is similar New-Service but it exposes
all the options from the CreateService API and allows you to specify service users.
.PARAMETER Name
Specify the name of the service.
.PARAMETER DisplayName
Specify the display name for the service.
.PARAMETER Type
Specify the service type.
.PARAMETER Start
Specify the service start type.
.PARAMETER Path
Specify the path to the service binary.
.PARAMETER LoadOrderGroup
Specify the load order group.
.PARAMETER Dependencies
Specify the list of dependencies.
.PARAMETER Username
Specify the username for the service.
.PARAMETER Password
Specify the password for the username.
.PARAMETER PassThru
Specify to return information about the service.
.PARAMETER MachineName
Specify the target computer.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Service.ServiceInstance
#>
function New-Win32Service {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position = 0)]
        [string]$Name,
        [string]$DisplayName,
        [NtCoreLib.Win32.Service.ServiceType]$Type = "Win32OwnProcess",
        [NtCoreLib.Win32.Service.ServiceStartType]$Start = "Demand",
        [NtCoreLib.Win32.Service.ServiceErrorControl]$ErrorControl = 0,
        [parameter(Mandatory, Position = 1)]
        [string]$Path,
        [string]$LoadOrderGroup,
        [string[]]$Dependencies,
        [string]$Username,
        [NtObjectManager.Utils.PasswordHolder]$Password,
        [switch]$PassThru,
        [string]$MachineName
    )

    $pwd = if ($null -ne $Password) {
        $Password.Password
    }
    $service = [NtCoreLib.Win32.Service.ServiceUtils]::CreateService($MachineName, $Name, $DisplayName, $Type, `
        $Start, $ErrorControl, $Path, $LoadOrderGroup, $Dependencies, $Username, $pwd)
    if ($PassThru) {
        $service
    }
}

<#
.SYNOPSIS
Delete a Win32 service.
.DESCRIPTION
This cmdlet deletes a Win32 service. This is basically the same as Remove-Service
but is available on PowerShell 5.1. Also directly supports specifying the machine name.
.PARAMETER Name
Specify the name of the service.
.PARAMETER MachineName
Specify the target computer.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-Win32Service {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position = 0)]
        [string]$Name,
        [string]$MachineName
    )

    [NtCoreLib.Win32.Service.ServiceUtils]::DeleteService($MachineName, $Name)
}

<#
.SYNOPSIS
Get the security descriptor for a service.
.DESCRIPTION
This cmdlet gets the security descriptor for a service or the SCM.
.PARAMETER Name
Specify the name of the service.
.PARAMETER ServiceControlManager
Specify to query the service control manager security descriptor.
.PARAMETER SecurityInformation
Specify the parts of the security descriptor to return.
.PARAMETER MachineName
Specify the target computer.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.SecurityDescriptor
#>
function Get-Win32ServiceSecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName="FromName")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName="FromName")]
        [string]$Name,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromScm")]
        [switch]$ServiceControlManager,
        [parameter(Position = 1)]
        [NtCoreLib.Security.Authorization.SecurityInformation]$SecurityInformation = "Owner, Group, Dacl, Label",
        [string]$MachineName
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromName" {
            [NtCoreLib.Win32.Service.ServiceUtils]::GetServiceSecurityDescriptor($MachineName, $Name, $SecurityInformation)
        }
        "FromScm" {
            [NtCoreLib.Win32.Service.ServiceUtils]::GetScmSecurityDescriptor($MachineName, $SecurityInformation)
        }
    }
}

<#
.SYNOPSIS
Set the security descriptor for a service.
.DESCRIPTION
This cmdlet sets the security descriptor for a service or the SCM.
.PARAMETER Name
Specify the name of the service.
.PARAMETER ServiceControlManager
Specify to set the service control manager security descriptor.
.PARAMETER SecurityInformation
Specify the parts of the security descriptor to set.
.PARAMETER SecurityDescriptor 
The security descriptor to set.
.PARAMETER MachineName
Specify the target computer.
.INPUTS
None
.OUTPUTS
None
#>
function Set-Win32ServiceSecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName="FromName")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName="FromName")]
        [string]$Name,
        [parameter(Mandatory, ParameterSetName="FromScm")]
        [switch]$ServiceControlManager,
        [parameter(Mandatory, Position = 1)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [parameter(Mandatory, Position = 2)]
        [NtCoreLib.Security.Authorization.SecurityInformation]$SecurityInformation,
        [string]$MachineName
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromName" {
            [NtCoreLib.Win32.Service.ServiceUtils]::SetServiceSecurityDescriptor($MachineName, $Name, $SecurityDescriptor, $SecurityInformation)
        }
        "FromScm" {
            [NtCoreLib.Win32.Service.ServiceUtils]::SetScmSecurityDescriptor($MachineName, $SecurityDescriptor, $SecurityInformation)
        }
    }
}

<#
.SYNOPSIS
Start a Win32 service.
.DESCRIPTION
This cmdlet starts a Win32 service. This is basically the same as Start-Service
but allows the user to specify the arguments to pass to the start callback.
.PARAMETER Name
Specify the name of the service.
.PARAMETER ArgumentList
Specify the list of arguments to the service.
.PARAMETER PassThru
Query for the service status after starting.
.PARAMETER MachineName
Specify the target computer.
.PARAMETER NoWait
Specify to not wait 30 seconds for the service to start.
.PARAMETER Trigger
Specify to try and use a service trigger to start the service.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Service.ServiceInstance
#>
function Start-Win32Service {
    [CmdletBinding(DefaultParameterSetName="FromStart")]
    param (
        [parameter(Mandatory, Position = 0)]
        [string]$Name,
        [parameter(ParameterSetName="FromStart")]
        [string[]]$ArgumentList,
        [parameter(ParameterSetName="FromStart")]
        [string]$MachineName,
        [parameter(Mandatory, ParameterSetName="FromTrigger")]
        [switch]$Trigger,
        [switch]$PassThru,
        [switch]$NoWait
    )

    try {
        switch ($PSCmdlet.ParameterSetName) {
            "FromStart" {
                [NtCoreLib.Win32.Service.ServiceUtils]::StartService($MachineName, $Name, $ArgumentList)
            }
            "FromTrigger" {
                $service_trigger = Get-Win32ServiceTrigger -Name $Name -Action Start | Select-Object -First 1
                if ($null -eq $service_trigger) {
                    throw "No service trigger available for $Name"
                }
                $service_trigger.Trigger()
            }
        }
        
        if (!$NoWait) {
            if (!(Wait-Win32Service -MachineName $MachineName -Name $Name -Status Running -TimeoutSec 30)) {
                Write-Error "Service didn't start in time."
                return
            }
        }
        if ($PassThru) {
            Get-Win32Service -Name $Name -MachineName $MachineName
        }
    }
    catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Tests a Win32 service state.
.DESCRIPTION
This cmdlet tests if a win32 service is in a fixed state.
.PARAMETER Name
Specify the name of the service.
.PARAMETER Status
Specify the status to test.
.PARAMETER MachineName
Specify the target computer.
.INPUTS
None
.OUTPUTS
Boolean
#>
function Test-Win32Service {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position = 0)]
        [string]$Name,
        [string]$MachineName,
        [parameter(Mandatory, Position = 1)]
        [NtCoreLib.Win32.Service.ServiceStatus]$Status
    )

    try {
        $service = Get-Win32Service -Name $Name -MachineName $MachineName
        return $service.Status -eq $Status
    }
    catch {
        Write-Error $_
        return $false
    }
}

<#
.SYNOPSIS
Restart a Win32 service.
.DESCRIPTION
This cmdlet restarts a Win32 service.
.PARAMETER Name
Specify the name of the service.
.PARAMETER ArgumentList
Specify the list of arguments to the service.
.PARAMETER PassThru
Query for the service status after starting.
.PARAMETER MachineName
Specify the target computer.
.PARAMETER NoWait
Specify to not wait 30 seconds for the service to start.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Service.ServiceInstance
#>
function Restart-Win32Service {
    [CmdletBinding(DefaultParameterSetName="FromStart")]
    param (
        [parameter(Mandatory, Position = 0)]
        [string]$Name,
        [parameter(ParameterSetName="FromStart")]
        [string[]]$ArgumentList,
        [parameter(ParameterSetName="FromStart")]
        [string]$MachineName,
        [switch]$PassThru,
        [switch]$NoWait
    )

    try {
        if (!(Test-Win32Service -Name $Name -MachineName $MachineName -Status Stopped)) {
            Send-Win32Service -Name $Name -MachineName $MachineName -Control Stop -ErrorAction Stop
        }

        Start-Win32Service -Name $Name -MachineName $MachineName -ArgumentList $ArgumentList -PassThru:$PassThru -NoWait:$NoWait
    }
    catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Send a control code to a Win32 service.
.DESCRIPTION
This cmdlet sends a control code to a Win32 service.
.PARAMETER Name
Specify the name of the service.
.PARAMETER Control
Specify the control code to send.
.PARAMETER CustomControl
Specify to send a custom control code. Typically in the range of 128 to 255.
.PARAMETER PassThru
Query for the service status after sending the code.
.PARAMETER MachineName
Specify the target computer.
.PARAMETER NoWait
Specify to not wait 30 seconds for the service control to be handled.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Service.ServiceInstance
#>
function Send-Win32Service {
    [CmdletBinding(DefaultParameterSetName="FromControl")]
    param (
        [parameter(Mandatory, Position = 0)]
        [string]$Name,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromControl")]
        [NtCoreLib.Win32.Service.ServiceControlCode]$Control,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromCustomControl")]
        [int]$CustomControl,
        [switch]$PassThru,
        [string]$MachineName,
        [parameter(ParameterSetName="FromControl")]
        [switch]$NoWait
    )

    try {
        $wait = switch($PSCmdlet.ParameterSetName) {
            "FromControl" {
                [NtCoreLib.Win32.Service.ServiceUtils]::ControlService($MachineName, $Name, $Control)
                !$NoWait
            }
            "FromCustomControl" {
                [NtCoreLib.Win32.Service.ServiceUtils]::ControlService($MachineName, $Name, $CustomControl)
                $false
            }
        }

        if ($wait) {
            $wait_state = switch($Control) {
                "Stop" {
                    Wait-Win32Service -MachineName $MachineName -Name $Name -Status Stopped -TimeoutSec 30
                }
                "Pause" {
                    Wait-Win32Service -MachineName $MachineName -Name $Name -Status Paused -TimeoutSec 30
                }
                "Continue" {
                    Wait-Win32Service -MachineName $MachineName -Name $Name -Status Running -TimeoutSec 30
                }
                default { 
                    # Anything else we just return success.
                    $true 
                }
            }

            if (!$wait_state) {
                Write-Error "Service didn't respond to control in time."
                return
            }
        }
        if ($PassThru) {
            Get-Win32Service -Name $Name -MachineName $MachineName
        }
    }
    catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Wait for a Win32 service status.
.DESCRIPTION
This cmdlet waits for a Win32 service to reach a certain status. Returns true if the status was reached. False if timed out or other error.
.PARAMETER Name
Specify the name of the service.
.PARAMETER Status
Specify the status to wait for.
.PARAMETER MachineName
Specify the target computer.
.PARAMETER TimeoutSec
Specify the timeout in seconds.
.INPUTS
None
.OUTPUTS
Boolean
#>
function Wait-Win32Service {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position = 0)]
        [string]$Name,
        [parameter(Mandatory, Position = 1)]
        [NtCoreLib.Win32.Service.ServiceStatus]$Status,
        [string]$MachineName,
        [int]$TimeoutSec = [int]::MaxValue
    )

    try {
        if (Test-Win32Service -Name $Name -MachineName $MachineName -Status $Status) {
            return $true
        }

        if ($TimeoutSec -le 0) {
            return $false
        }

        $timeout_ms = $TimeoutSec * 1000
        while ($timeout_ms -gt 0) {
            $service = Get-Win32Service -Name $Name -MachineName $MachineName
            if ($service.Status -eq $Status) {
                return $true
            }

            Start-Sleep -Milliseconds 250
            $timeout_ms -= 250
        }
    } catch {
        Write-Error $_
    }
    return $false
}

<#
.SYNOPSIS
Get the configuration for a service or all services.
.DESCRIPTION
This cmdlet gets the configuration for a service or all services.
.PARAMETER Name
Specify the name of the service.
.PARAMETER ServiceType
Specify the types of services to return when querying all services. Defaults to all user services.
.PARAMETER MachineName
Specify the target computer.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Service.ServiceConfig[]
#>
function Get-Win32ServiceConfig {
    [CmdletBinding(DefaultParameterSetName="All")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName="FromName")]
        [string]$Name,
        [parameter(ParameterSetName = "All")]
        [NtCoreLib.Win32.Service.ServiceType]$ServiceType = [NtCoreLib.Win32.Service.ServiceUtils]::GetServiceTypes(),
        [string]$MachineName
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromName" {
            [NtCoreLib.Win32.Service.ServiceUtils]::GetServiceConfiguration($MachineName, $Name)
        }
        "All" {
            [NtCoreLib.Win32.Service.ServiceUtils]::GetServiceConfiguration($MachineName, $ServiceType) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get the configuration for a service or all services.
.DESCRIPTION
This cmdlet gets the configuration for a service or all services.
.PARAMETER Name
Specify the name of the service.
.PARAMETER ServiceType
Specify the types of services to return when querying all services. Defaults to all user services.
.PARAMETER MachineName
Specify the target computer.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Service.ServiceConfig[]
#>
function Get-Win32ServiceConfig {
    [CmdletBinding(DefaultParameterSetName="All")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName="FromName")]
        [string]$Name,
        [parameter(ParameterSetName = "All")]
        [NtCoreLib.Win32.Service.ServiceType]$ServiceType = [NtCoreLib.Win32.Service.ServiceUtils]::GetServiceTypes(),
        [string]$MachineName
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromName" {
            [NtCoreLib.Win32.Service.ServiceUtils]::GetServiceConfiguration($MachineName, $Name)
        }
        "All" {
            [NtCoreLib.Win32.Service.ServiceUtils]::GetServiceConfiguration($MachineName, $ServiceType) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get the service triggers for a service.
.DESCRIPTION
This cmdlet gets the service triggers for a service.
.PARAMETER Name
The name of the service.
.PARAMETER MachineName
Specify the target computer.
.PARAMETER Action
Specify an action to filter on.
.PARAMETER Service
Specify a service object.
.INPUTS
NtCoreLib.Win32.Service.ServiceInstance[]
.OUTPUTS
NtCoreLib.Win32.Service.Triggers.ServiceTriggerInformation[]
.EXAMPLE
Get-Win32ServiceTrigger -Name "WebClient"
Get the service triggers for the WebClient service.
#>
function Get-Win32ServiceTrigger { 
    [CmdletBinding(DefaultParameterSetName="FromName")]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromName")]
        [string]$Name,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromService", ValueFromPipeline)]
        [NtCoreLib.Win32.Service.ServiceInstance]$Service,
        [NtCoreLib.Win32.Service.Triggers.ServiceTriggerAction]$Action = 0,
        [string]$MachineName
    )

    PROCESS {
        if ($PSCmdlet.ParameterSetName -eq "FromName") {
            $service = Get-Win32Service -MachineName $MachineName -Name $Name
        }
        if ($null -ne $service) {
            $triggers = $service.Triggers
            if ($Action -ne 0) {
                $triggers = $triggers | Where-Object Action -eq $Action
            }
            $triggers | Write-Output
        }
    }
}

<#
.SYNOPSIS
Gets a list of win32 services.
.DESCRIPTION
This cmdlet gets a list of all win32 services. 
.PARAMETER State
Specify the state of the services to get.
.PARAMETER Type
Specify to filter the services to specific types only.
.PARAMETER Name
Specify names to lookup.
.PARAMETER MachineName
Specify the target computer.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Service.ServiceInstance[]
.EXAMPLE
Get-Win32Service
Get all services.
.EXAMPLE
Get-Win32Service -State Active
Get all active services.
.EXAMPLE
Get-Win32Service -State All -Type UserService
Get all user services.
.EXAMPLE
Get-Win32Service -ProcessId 1234
Get services running in PID 1234.
.EXAMPLE
Get-Win32Service -Name WebClient
Get the WebClient service.
#>
function Get-Win32Service {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(ParameterSetName = "All")]
        [NtCoreLib.Win32.Service.ServiceState]$State = "All",
        [parameter(ParameterSetName = "All")]
        [NtCoreLib.Win32.Service.ServiceType]$Type = 0,
        [parameter(Mandatory, ParameterSetName = "FromName", Position = 0)]
        [string[]]$Name,
        [parameter(Mandatory, ParameterSetName = "FromPid", Position = 0)]
        [int[]]$ProcessId,
        [string]$MachineName
    )

    PROCESS {
        switch ($PSCmdlet.ParameterSetName) {
            "All" {
                if ($Type -eq 0) {
                    $Type = [NtCoreLib.Win32.Service.ServiceUtils]::GetServiceTypes()
                }
                [NtCoreLib.Win32.Service.ServiceUtils]::GetServices($MachineName, $State, $Type) | Write-Output
            }
            "FromName" {
                foreach ($n in $Name) {
                    [NtCoreLib.Win32.Service.ServiceUtils]::GetService($MachineName, $n) | Write-Output
                }
            }
            "FromPid" {
                Get-Win32Service -State Active -MachineName $MachineName | Where-Object {$_.ProcessId -in $ProcessId}
            }
        }
    }
}

<#
.SYNOPSIS
Get an extended right from Active Directory.
.DESCRIPTION
This cmdlet gets an extended right from Active Directory. This can be slow.
.PARAMETER RightId
Specify the GUID for the right.
.PARAMETER Attribute
Specify to get the propert set right for an attribute which is a property.
.PARAMETER Domain
Specify the domain or server name to query for the extended rights. Defaults to current domain.
.PARAMETER Name
Specify the common name of the extended right to get.
.PARAMETER SchemaClass
Specify a schema class to get extended rights.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.DirectoryService.DirectoryServiceExtendedRight[]
.EXAMPLE
Get-DsExtendedRight
Get all extended rights.
.EXAMPLE
Get-DsExtendedRight -Domain sales.domain.com
Get all extended rights on the sales.domain.com domain.
.EXAMPLE
Get-DsExtendedRight -RightId "e48d0154-bcf8-11d1-8702-00c04fb96050"
Get the Public-Information extended right by GUID.
.EXAMPLE
Get-DsExtendedRight -Attribute $attr
Get the property set for the attribute.
#>
function Get-DsExtendedRight {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromGuid", Position = 0)]
        [guid]$RightId,
        [parameter(Mandatory, ParameterSetName = "FromName")]
        [string]$Name,
        [parameter(Mandatory, ParameterSetName = "FromAttribute")]
        [NtCoreLib.Win32.DirectoryService.DirectoryServiceSchemaAttribute]$Attribute,
        [parameter(Mandatory, ParameterSetName = "FromSchemaClass")]
        [NtCoreLib.Win32.DirectoryService.DirectoryServiceSchemaClass]$SchemaClass,
        [parameter(ParameterSetName = "FromSchemaClass")]
        [parameter(ParameterSetName = "FromGuid")]
        [parameter(ParameterSetName = "FromName")]
        [parameter(ParameterSetName = "All")]
        [string]$Domain
    )

    switch ($PSCmdlet.ParameterSetName) {
        "All" {
            [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetExtendedRights($Domain) | Write-Output
        }
        "FromGuid" {
            [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetExtendedRight($Domain, $RightId)
        }
        "FromName" {
            [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetExtendedRight($Domain, $Name)
        }
        "FromSchemaClass" {
            [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetExtendedRights($Domain, $SchemaClass.SchemaId)
        }
        "FromAttribute" {
            if ($null -ne $Attribute.AttributeSecurityGuid) {
                [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetExtendedRight($Attribute.Domain, $Attribute.AttributeSecurityGuid)
            }
        }
    }
}

<#
.SYNOPSIS
Get a schema class from Active Directory.
.DESCRIPTION
This cmdlet gets a schema class from Active Directory. This can be slow.
.PARAMETER SchemaId
Specify the GUID for the schema class.
.PARAMETER Domain
Specify the domain or server name to query for the schema class. Defaults to current domain.
.PARAMETER Name
Specify the LDAP name for the schema class to get.
.PARAMETER Parent
Specify an existing schema class and get its parent class.
.PARAMETER Recurse
Specify to recurse the parent relationships and return all objects.
.PARAMETER Inferior
Specify to return inferior classes which can be created underneath this class.
.PARAMETER IncludeAuxiliary
Specify to return include auxiliary classes with the class.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.DirectoryService.DirectoryServiceSchemaClass[]
.EXAMPLE
Get-DsSchemaClass
Get all schema classes.
.EXAMPLE
Get-DsSchemaClass -Domain sales.domain.com
Get all schema classes on the sales.domain.com domain.
.EXAMPLE
Get-DsSchemaClass -SchemaId "BF967ABA-0DE6-11D0-A285-00AA003049E2"
Get the user schema class by GUID.
.EXAMPLE
Get-DsSchemaClass -Name "user"
Get the user schema class by LDAP name.
.EXAMPLE
Get-DsSchemaClass -Name "user" -IncludeAuxiliary
Get the user schema class by LDAP name and include all auxiliary classes.
.EXAMPLE
Get-DsSchemaClass -Parent $cls
Get the parent schema class for another class.
.EXAMPLE
Get-DsSchemaClass -Parent $cls -Recurse
Get the parent schema class for another class and recurse to top.
#>
function Get-DsSchemaClass {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromGuid")]
        [guid]$SchemaId,
        [parameter(Mandatory, ParameterSetName = "FromName", Position = 0, ValueFromPipelineByPropertyName)]
        [string]$Name,
        [parameter(Mandatory, ParameterSetName = "FromParent", Position = 0)]
        [NtCoreLib.Win32.DirectoryService.DirectoryServiceSchemaClass]$Parent,
        [parameter(ParameterSetName = "All")]
        [parameter(ParameterSetName = "FromName")]
        [parameter(ParameterSetName = "FromGuid")]
        [string]$Domain,
        [parameter(ParameterSetName = "FromParent")]
        [parameter(ParameterSetName = "FromName")]
        [parameter(ParameterSetName = "FromGuid")]
        [switch]$Recurse,
        [parameter(ParameterSetName = "FromParent")]
        [parameter(ParameterSetName = "FromName")]
        [parameter(ParameterSetName = "FromGuid")]
        [switch]$Inferior,
        [parameter(ParameterSetName = "FromParent")]
        [parameter(ParameterSetName = "FromName")]
        [parameter(ParameterSetName = "FromGuid")]
        [switch]$IncludeAuxiliary
    )

    PROCESS {
        $cls = switch ($PSCmdlet.ParameterSetName) {
            "All" {
                [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetSchemaClasses($Domain) | Write-Output
            }
            "FromGuid" {
                [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetSchemaClass($Domain, $SchemaId)
            }
            "FromName" {
                [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetSchemaClass($Domain, $Name)
            }
            "FromParent" {
                if (("" -ne $Parent.SubClassOf) -and ($Parent.SubClassOf -ne $Parent.Name)) {
                    Get-DsSchemaClass -Domain $Parent.Domain -Name $Parent.SubClassOf
                }
            }
        }

        if ($null -eq $cls) {
            return
        }

        if ($Inferior) {
            $cls.PossibleInferiors | ForEach-Object { Get-DsSchemaClass -Domain $Domain -Name $_ -IncludeAuxiliary:$IncludeAuxiliary }
        } else {
            $cls
            if ($IncludeAuxiliary) {
                $cls.AuxiliaryClasses | ForEach-Object { Get-DsSchemaClass -Domain $Domain -Name $_.Name }
            }
        }

        if ($Recurse) {
            Get-DsSchemaClass -Parent $cls -Recurse -Inferior:$Inferior -IncludeAuxiliary:$IncludeAuxiliary
        }
    }
}

<#
.SYNOPSIS
Get a schema attribute from Active Directory.
.DESCRIPTION
This cmdlet gets a schema attribute from Active Directory. This can be slow.
.PARAMETER SchemaId
Specify the GUID for the schema attribute.
.PARAMETER Domain
Specify the domain or server name to query for the schema attribute. Defaults to current domain.
.PARAMETER Name
Specify the LDAP name for the schema attribute to get.
.PARAMETER Attribute
Specify to get the schema class for an attribute.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.DirectoryService.DirectoryServiceSchemaAttribute[]
.EXAMPLE
Get-DsSchemaAttribute
Get all schema attributes.
.EXAMPLE
Get-DsSchemaAttribute -Domain sales.domain.com
Get all schema attributes on the sales.domain.com domain.
.EXAMPLE
Get-DsSchemaAttribute -SchemaId "28630EBB-41D5-11D1-A9C1-0000F80367C1"
Get the user principal name attribute by GUID.
.EXAMPLE
Get-DsSchemaAttribute -Name "lDAPDisplayName"
Get the user principal name attribute by LDAP name.
#>
function Get-DsSchemaAttribute {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromGuid")]
        [guid]$SchemaId,
        [parameter(Mandatory, ParameterSetName = "FromName", Position = 0)]
        [string]$Name,
        [parameter(ParameterSetName = "All")]
        [parameter(ParameterSetName = "FromName")]
        [parameter(ParameterSetName = "FromGuid")]
        [parameter(ParameterSetName = "FromAttribute")]
        [string]$Domain,
        [parameter(Mandatory, ParameterSetName = "FromAttribute", ValueFromPipeline)]
        [NtCoreLib.Win32.DirectoryService.DirectoryServiceSchemaClassAttribute]$Attribute
    )

    PROCESS {
        switch ($PSCmdlet.ParameterSetName) {
            "All" {
                [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetSchemaAttributes($Domain) | Write-Output
            }
            "FromGuid" {
                [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetSchemaAttribute($Domain, $SchemaId)
            }
            "FromName" {
                [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetSchemaAttribute($Domain, $Name)
            }
            "FromAttribute" {
                [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetSchemaAttribute($Domain, $Attribute.Name)
            }
        }
    }
}

<#
.SYNOPSIS
Get the SID for an object from Active Directory.
.DESCRIPTION
This cmdlet gets the SID for an object from Active Directory. This can be slow.
.PARAMETER DistinguishedName
Specify the distinguished name of the object.
.PARAMETER Object
Specify the object directory entry.
.PARAMETER Domain
Specify the domain or server name to query for the object. Defaults to current domain.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.Sid
.EXAMPLE
Get-DsObjectSid -DistinguishedName "CN=Bob,CN=Users,DC=domain,DC=com"
Get the object SID for a user object by name.
.EXAMPLE
Get-DsObjectSid -DistinguishedName "CN=Bob,CN=Users,DC=sales,DC=domain,DC=com" -Domain SALES
Get the object SID for a user object by name in the SALES domain.
.EXAMPLE
Get-DsObjectSid -Object $obj
Get the object SID from a user object.
#>
function Get-DsObjectSid {
    [CmdletBinding(DefaultParameterSetName = "FromName")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromName", Position = 0)]
        [alias("dn")]
        [string]$DistinguishedName,
        [parameter(ParameterSetName = "FromName")]
        [string]$Domain,
        [parameter(Mandatory, ParameterSetName = "FromObject")]
        [System.DirectoryServices.DirectoryEntry]$Object
    )

    switch ($PSCmdlet.ParameterSetName) {
        "FromName" {
            [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetObjectSid($Domain, $DistinguishedName)
        }
        "FromObject" {
            [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetObjectSid($Object)
        }
    }
}

<#
.SYNOPSIS
Get the schema class for an object from Active Directory.
.DESCRIPTION
This cmdlet gets the schema class for an object from Active Directory. This can be slow.
.PARAMETER DistinguishedName
Specify the distinguished name of the object.
.PARAMETER Object
Specify the object directory entry.
.PARAMETER Domain
Specify the domain or server name to query for the object. Defaults to current domain.
.PARAMETER Recurse
Specify to get all schema classes for the object in the inheritance chain.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.DirectoryService.DirectoryServiceSchemaClass[]
.EXAMPLE
Get-DsObjectSchemaClass -DistinguishedName "CN=Bob,CN=Users,DC=domain,DC=com"
Get the schema class for a user object by name.
.EXAMPLE
Get-DsObjectSchemaClass -DistinguishedName "CN=Bob,CN=Users,DC=sales,DC=domain,DC=com" -Domain SALES
Get the schema class for a user object by name in the SALES domain.
.EXAMPLE
Get-DsObjectSchemaClass -Object $obj
Get the schema class from a user object.
.EXAMPLE
Get-DsObjectSchemaClass -DistinguishedName "CN=Bob,CN=Users,DC=domain,DC=com" -Recurse
Get the all inherited schema class for a user object by name.
#>
function Get-DsObjectSchemaClass {
    [CmdletBinding(DefaultParameterSetName = "FromName")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromName", Position = 0)]
        [alias("dn")]
        [string]$DistinguishedName,
        [parameter(ParameterSetName = "FromName")]
        [string]$Domain,
        [parameter(Mandatory, ParameterSetName = "FromObject")]
        [System.DirectoryServices.DirectoryEntry]$Object,
        [switch]$Recurse
    )

    if ($PSCmdlet.ParameterSetName -eq "FromName") {
        $Object = [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetObject($Domain, $DistinguishedName)
    }

    $obj_class = $Object.objectClass
    if ($obj_class -eq $null -or $obj_class.Count -eq 0) {
        return
    }

    Get-DsSchemaClass -Name $obj_class[-1] -Recurse:$Recurse
}

<#
.SYNOPSIS
Get the dsHeuristics for the domain.
.DESCRIPTION
This cmdlet gets the dsHeuristics value for the domain.
.PARAMETER Domain
Specify the domain or server name to query for the object. Defaults to current domain.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.DirectoryService.DirectoryServiceHeuristics[]
.EXAMPLE
Get-DsHeuristics
Get the dsHeuristics for the current domain.
.EXAMPLE
Get-DsHeuristics -Domain SALES
Get the dsHeuristics for the SALES domain.
#>
function Get-DsHeuristics {
    param(
        [string]$Domain
    )
    [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetDsHeuristics($Domain)
}

<#
.SYNOPSIS
Get the sDRightsEffective for an object.
.DESCRIPTION
This cmdlet gets the constructed sDRightsEffective value for an object. This represents the write access to the SD the caller has.
.PARAMETER Domain
Specify the domain or server name to query for the object. Defaults to current domain.
.PARAMETER DistinguishedName
Specify the distinguished name of the object.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.SecurityInformation
.EXAMPLE
Get-DsSDRightsEffective -DistinguishedName "DC=domain,DC=local"
Get the sDRightsEffective for an object.
.EXAMPLE
Get-DsHeuristics -Domain SALES -DistinguishedName "DC=domain,DC=local"
Get the sDRightsEffective for an object in the SALES domain.
#>
function Get-DsSDRightsEffective {
    [CmdletBinding()]
    param(
        [alias("dn")]
        [parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [string]$DistinguishedName,
        [string]$Domain
    )

    PROCESS {
        [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetSDRightsEffective($Domain, $DistinguishedName)
    }
}

<#
.SYNOPSIS
Search for the distinguished name of the object which represents the SID.
.DESCRIPTION
This cmdlet searches for the object distinguished name for a SID.
.PARAMETER Sid
Specify the SID to lookup.
.PARAMETER Domain
Specify the domain or server name to query for the object. Defaults to current domain's global catalog.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.DirectoryService.DirectoryServiceSecurityPrincipal
.EXAMPLE
Search-DsObjectSid -Sid (Get-NtSid)
Get the name of the object for the current SID.
#>
function Search-DsObjectSid {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [string]$Domain
    )

    PROCESS {
        [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::FindObjectFromSid($Domain, $Sid)
    }
}
