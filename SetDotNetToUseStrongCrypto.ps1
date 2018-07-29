Function Test-RegistryValue
{
    [CmdletBinding()]
    Param
    (
        # Registy key path
        [Parameter(Mandatory)]
        [string] $Path,
        # Registry property name
        [Parameter(Mandatory)]
        [string] $Name
    )
    Process
    {
        try
        {
            Write-Verbose "Checking registry key '$Path' for property '$Name'"
            $exists = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if (($null -eq $exists) -or ($exists.Length -eq 0))
            {
                return $false
            }
            else
            {
                return $true
            }
        }
        catch
        {
            return $false
        }
    }
}

Function Add-RegistryKeyAndProperty
{
    [CmdletBinding()]
    Param
    (
        # Registry key path
        [Parameter(Mandatory)]
        [string] $Path,
        # Registry property name
        [Parameter(Mandatory)]
        [string] $Name,
        # Registry property type
        [Parameter(Mandatory)]
        [string] $PropertyType,
        # Registry property value
        [Parameter(Mandatory)]
        [object]
        $Value
    )
    Process
    {
        if ((Test-RegistryValue -Path $Path -Name $Name) -eq $false)
        {
            Write-Debug "Creating missing Key '$Path' Property '$Name' with Value '$Value' of Type '$PropertyType'"
            if ((Test-Path -Path $Path) -eq $false)
            {
                New-Item -Path $Path -f
            }

            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType
        }
        else
        {
            Write-Information "Key '$Path' Property '$Name' already exist"
        }
    }
}

Function Set-StrongCrypto
{
    [CmdletBinding()]
    Param
    (
    )
    Process
    {
        $RegistryPropertyType = "DWord"
        $SystemDefaultTlsVersionsPropertyName = "SystemDefaultTlsVersions"
        $SystemDefaultTlsVersionsValue = 1
        $SchUseStrongCryptoPropertyName = "SchUseStrongCrypto"
        $SchUseStrongCryptoValue = 1

        [string[]]$registryPathsForDotnetTls =
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319",
            "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727",
            "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"

        foreach ($registryPath in $registryPathsForDotnetTls)
        {
            Add-RegistryKeyAndProperty -Path $registryPath -Name $SystemDefaultTlsVersionsPropertyName -Value $SystemDefaultTlsVersionsValue -PropertyType $RegistryPropertyType
            Add-RegistryKeyAndProperty -Path $registryPath -Name $SchUseStrongCryptoPropertyName -Value $SchUseStrongCryptoValue -PropertyType $RegistryPropertyType
        }

        $DisabledByDefaultPropertyName = "DisabledByDefault"
        $DisabledByDefaultFalseValue = 0
        $EnabledPropertyName = "Enabled"
        $EnabledtTrueValue = 1
        $EnabledtFalseValue = 0
        [string[]]$registryPathsForWindowsTls =
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client",
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"

        foreach ($registryPath in $registryPathsForWindowsTls)
        {
            if ($registryPath.Contains("SSL 3.0"))
            {
                Add-RegistryKeyAndProperty -Path $registryPath -Name $EnabledPropertyName -Value $EnabledtFalseValue -PropertyType $RegistryPropertyType
            }
            else
            {
                Add-RegistryKeyAndProperty -Path $registryPath -Name $DisabledByDefaultPropertyName -Value $DisabledByDefaultFalseValue -PropertyType $RegistryPropertyType
                Add-RegistryKeyAndProperty -Path $registryPath -Name $EnabledPropertyName -Value $EnabledtTrueValue -PropertyType $RegistryPropertyType
            }
        }

        $DefaultSecureProtocolsPropertyName = "DefaultSecureProtocols"
        $DefaultSecureProtocolsValue = 0xA00 # 0xA00 = TLSv1.1 (0x200) + TLSv1.2 (0x800)
        [string[]]$registryPathsForWinHttpTls =
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"

        foreach ($registryPath in $registryPathsForWinHttpTls)
        {
            Add-RegistryKeyAndProperty -Path $registryPath -Name $DefaultSecureProtocolsPropertyName -Value $DefaultSecureProtocolsValue -PropertyType $RegistryPropertyType
        }

        $registryPathsForInternetExplorerTls = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
        $SecureProtocolsPropertyName = "SecureProtocols"
        $SecureProtocolsValue = 0xA00 # 0xA00 = TLSv1.1 (0x200) + TLSv1.2 (0x800)
        Add-RegistryKeyAndProperty -Path $registryPathsForInternetExplorerTls -Name $SecureProtocolsPropertyName -Value $SecureProtocolsValue -PropertyType $RegistryPropertyType
    }
}
