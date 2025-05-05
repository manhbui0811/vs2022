#
# This script launches the VC redist executable and handles certain error scenarios.
#
param(
    [Parameter(Mandatory=$true)][String][ValidateNotNullOrEmpty()]$PayloadDirectory,
    [Parameter(Mandatory=$true)][String][ValidateSet("arm64","x64","x86")]$Architecture,
    [Parameter(Mandatory=$true)][String][ValidateNotNullOrEmpty()]$LogFile,
    [Parameter(Mandatory=$false)][String]$VersionToInstall
)

#
# Variables and helper functions
#

# Use transcript to log all output
$envTemp = [Environment]::GetEnvironmentVariable('TEMP', 'User')
$date = Get-Date -Format "yyyyMMddHHmmss"
$transcriptPath = "$envTemp\dd_vcredist_wrapper_" + $Architecture + "_" + $date + ".log"
Start-Transcript -Path $transcriptPath

# Gather VC runtime version information in registry and files, generating appropriate output
Function Collect-Version-Information($outputString)
{
    # Get registry version information
    $vcrtRegVersionNative = $missingVersion
    $vcrtRegVersionWOW = $missingVersion
    if (![string]::IsNullOrEmpty($vcrtRegKeyPathNative) -and (Test-Path $vcrtRegKeyPathNative)) {
        $vcrtRegKeyNative = Get-ItemProperty -Path $vcrtRegKeyPathNative
        $vcrtRegVersionNative = "$($vcrtRegKeyNative.Major).$($vcrtRegKeyNative.Minor).$($vcrtRegKeyNative.Bld).$($vcrtRegKeyNative.Rbld)"
    }
    if (![string]::IsNullOrEmpty($vcrtRegKeyPathWOW) -and (Test-Path $vcrtRegKeyPathWOW)) {
        $vcrtRegKeyWOW = Get-ItemProperty -Path $vcrtRegKeyPathWOW
        $vcrtRegVersionWOW = "$($vcrtRegKeyWOW.Major).$($vcrtRegKeyWOW.Minor).$($vcrtRegKeyWOW.Bld).$($vcrtRegKeyWOW.Rbld)"
    }

    $regVersionToCheck = $vcrtRegVersionNative
    if (($installType -eq [InstallType]::X64Native) -or ($installType -eq [InstallType]::Arm64Native) -and ($vcrtRegVersionNative -ne $vcrtRegVersionWOW)) {
        $vcrtRegVersion = "registry version mismatch"
        Write-Host "$outputString registry versions"
        if ($vcrtRegVersionNative -ne $missingVersion) {
            Write-Host "  native: $vcrtRegVersionNative"
        } else {
            Write-Host "  native: $missingVersionOutput"
        }
        if ($vcrtRegVersionWOW -ne $missingVersion) {
            Write-Host "  WOW:    $vcrtRegVersionWOW"
        } else {
            Write-Host "  WOW:    $missingVersionOutput"
        }
        $regVersionToCheck = $null
    } elseif ($installType -eq [InstallType]::X86OnX64) {
        $regVersionToCheck = $vcrtRegVersionWOW
    }

    if ($regVersionToCheck -ne $null) {
       if ($regVersionToCheck -ne $missingVersion) {
        $vcrtRegVersion = $regVersionToCheck
        Write-Host "$outputString registered version: $vcrtRegVersion"
        } else {
            Write-Host "No version registered"
        }
    }

    # Get file version information

    $vcrtFileVersion = $null
    Foreach ($redistFile in $allRedistFiles) {
        if (Test-Path -path "$systemDir\$redistFile") {
            $redistFileVersion = (Get-Item -LiteralPath "$systemDir\$redistFile").VersionInfo.FileVersionRaw
            $redistFileVersions += @{ $redistFile = $redistFileVersion }
            if ($vcrtFileVersion -eq $null) {
                $vcrtFileVersion = $redistFileVersion
            } elseif ($redistFileVersion -ne $vcrtFileVersion) {
                $vcrtFileVersion = "multiple versions found"
            }
        } else {
            $redistFileVersions += @{ $redistFile = $missingVersion }
        }
    }
    if ($vcrtFileVersion -eq $null) {
        $vcrtFileVersion = "no VC runtime files installed"
    }

    Write-Host "$outputString file version: $vcrtFileVersion"

    # If the registry and all file versions do not agree, list each file and its version

    $vcrtVersionConsistent = $true
    $outputStringLowerCase = $outputString.ToLower()
    if ($vcrtRegVersion -ne $vcrtFileVersion) {
        Write-Host "Inconsistent VC runtime install detected: registry version does not match file version"
        $vcrtVersionConsistent = $false
        $skipSoftRebootCheckReasons += "$outputStringLowerCase registry version does not match $outputStringLowerCase file version"
    } 
    if ($vcrtFileVersion -eq "multiple versions found") {
        Write-Host "Inconsistent VC runtime install detected: not all files have same version"
        $vcrtVersionConsistent = $false
        $skipSoftRebootCheckReasons += "not all $outputStringLowerCase files have same version"
    }
    if (! $vcrtVersionConsistent ) {
        Foreach ($redistFile in $allRedistFiles) {
            $redistFileVersionValue = $redistFileVersions[$redistFile]
            if ($redistFileVersionValue -eq $missingVersion) { $redistFileVersionValue = "not installed"}
            Write-Host "  ${redistFile}:  $redistFileVersionValue"
        }
        $vcrtVersionConsistent = $false
    }

    $vcrtVersion = $vcrtRegVersion
    if ($vcrtVersionConsistent -eq $false) {
        $vcrtVersion = $null
    }

    return $vcrtVersionConsistent, $vcrtVersion
}

#
# Main execution sequence
#

# Initialize variables

$envMachineArch = [Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE", 'Machine');
$envWINDIR = [Environment]::GetEnvironmentVariable('WINDIR', 'Machine')

# These variables are initialized to default x64 native values and overridden as appropriate:
#   $installType = one of { X64Native, X86OnX64, X86Native }
#   $systemDir = where to find installed files
#   $registryPath[Native,WOW] = the paths to the Native and WOW registry keys

enum InstallType {
    Arm64Native
    X64Native
    X86OnX64
    X86Native
}

# Setting $systemDir needs to account for System32 redirection on 64-bit processors:
#
#   MachineArch Process  VCRTArch   TargetDirectory SystemDirValue
#   x64         64-bit   x64        System32        System32
#   x64         32-bit   x64        System32        Sysnative (avoids redirection to SysWOW64)
#   x64         64-bit   x86        SysWOW64        SysWOW64
#   x64         32-bit   x86        SysWOW64        System32 (redirects to SysWOW64)
#   x86         32-bit   x86        System32        System32
# arm64         64-bit arm64        System32        System32

$installType = [InstallType]::X64Native
$is64BitPS = [IntPtr]::Size -eq 8
$systemDir = "$envWINDIR\System32"
if ($Architecture -eq "x64" -and $is64BitPS -eq $false) {
    $systemDir = "$envWINDIR\Sysnative"
} elseif ($Architecture -eq "x86" -and $is64BitPS -eq $true) {
    $systemDir = "$envWINDIR\SysWOW64"
}

# Registry keys
$vcrtRegKeyPathNative = "HKLM:\Software\Microsoft\VisualStudio\14.0\VC\Runtimes\$Architecture"
$vcrtRegKeyPathWOW = "HKLM:\Software\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\$Architecture"
if ($envMachineArch -eq 'AMD64' -and $Architecture -eq 'x86') {
    $installType = [InstallType]::X86OnX64
} elseif ($envMachineArch -eq 'X86' -and $Architecture -eq 'x86') { 
    $installType = [InstallType]::X86Native
    $vcrtRegKeyPathWOW = ""
} elseif ($envMachineArch -eq 'ARM64') { 
    $installType = [InstallType]::Arm64Native
}

# The value "0.0.0.0" indicates the registry key is empty or the file is not present,
# which typically indicates the VCRT is not installed or only partially installed.
$missingVersion = "0.0.0.0"
$missingVersionOutput = "not found"

# List of VCRT files
$redistSharedFiles = @(
    "concrt140.dll",
    "mfc140.dll",
    "mfc140chs.dll",
    "mfc140cht.dll",
    "mfc140deu.dll",
    "mfc140enu.dll",
    "mfc140esn.dll",
    "mfc140fra.dll",
    "mfc140ita.dll",
    "mfc140jpn.dll",
    "mfc140kor.dll",
    "mfc140rus.dll",
    "mfc140u.dll",
    "msvcp140.dll",
    "msvcp140_1.dll",
    "msvcp140_2.dll",
    "msvcp140_atomic_wait.dll",
    "msvcp140_codecvt_ids.dll",
    "vcamp140.dll",
    "vccorlib140.dll",
    "vcomp140.dll",
    "vcruntime140.dll",
    "vcruntime140_threads.dll"
)
$redistIntelFiles = @(
    "mfcm140.dll",
    "mfcm140u.dll"
)
$redistX64Files = @(
    "vcruntime140_1.dll"
)

if ($Architecture -eq 'x64') {
    $allRedistFiles = @($redistSharedFiles) + @($redistIntelFiles) + @($redistX64Files)
} elseif ($Architecture -eq 'arm64') {
    $allRedistFiles = @($redistSharedFiles) + @($redistX64Files)
} else {
    $allRedistFiles = @($redistSharedFiles) + @($redistIntelFiles)
}

# Begin output

Write-Host "Installing Visual C++ Redist"
Write-Host "Inputs:"
Write-Host "  PayloadDirectory: $PayloadDirectory"
Write-Host "  Architecture:     $Architecture"
Write-Host "  LogFile:          $LogFile"
Write-Host "  VersionToInstall: $VersionToInstall" 
Write-Host "Environment:"
Write-Host "  WINDIR:           $envWINDIR"
Write-Host "  TEMP:             $envTemp" 
Write-Host "  system directory: $systemDir"
Write-Host "  native reg. key:  $vcrtRegKeyPathNative"
Write-Host "  WOW64 reg. key:   $vcrtRegKeyPathWOW"
Write-Host "Installing $Architecture Visual C++ Runtime on $envMachineArch system"

$checkForSoftReboot = $true
$skipSoftRebootCheckReasons = @()

# Lookup current versions in registry and files to determine if there is 
# a consistent VC Runtime installation. An inconsistent initial install does not
# disable soft-reboot since it can be a valid state (vc_redist installs a full
# set of runtime files, then an MSM install updates only a subset of files).

$vcrtIsInitialInstallConsistent, $vcrtUpdatedVersion = Collect-Version-Information("Initial")
if (! $vcrtIsInitialInstallConsistent ) {
    Write-Host "Information: initial VC runtime install is not consistent"
}

# Run VCRT install command with parameters used for VS installs
#   command: $PayloadDirectory\vc_redist.$Architecture.exe /q /norestart /log $LogFile
#   example: VC_redist.x64.exe /q /norestart /log <logfilename>
# Use Start-Process to wait for exit and pass-thru the exit code

$vcrtExePath=-join($PayloadDirectory, "\\VC_redist.", $Architecture, ".exe")
$vcrtInstallerVersion = (Get-Item -LiteralPath $vcrtExePath).VersionInfo.FileVersionRaw
Write-Host "Redist Installer Version: $vcrtInstallerVersion"

$vcrtProcess = Start-Process -FilePath $vcrtExePath -ArgumentList "/q /norestart /log $LogFile" -Wait -PassThru
$vcrtProcessExitCode = $vcrtProcess.ExitCode
Write-Host "Redist Exit Code:   $vcrtProcessExitCode"

# Gather updated versions in registry and files

$vcrtIsUpdatedInstallConsistent, $vcrtUpdatedVersion = Collect-Version-Information("Updated")
if (! $vcrtIsUpdatedInstallConsistent ) {
    Write-Host "Skipping soft-reboot check: updated VC runtime install is not consistent"
    $checkForSoftReboot = $false
}

if ((! [string]::IsNullOrEmpty($VersionToInstall)) -and ($vcrtUpdatedVersion -ne $VersionToInstall)) {
    $msg = "updated VC runtime version $vcrtUpdatedVersion does not match expected version $VersionToInstall"
    Write-Host "Skipping soft-reboot check: $msg"
    $checkForSoftReboot = $false
    $skipSoftRebootCheckReasons += $msg
}

$returnCode=$vcrtProcessExitCode
if ($vcrtProcessExitCode -ne 3010) {
    $msg = "redist exit code was not ERROR_SUCCESS_REBOOT_REQUIRED (3010)"
    Write-Host "Skipping soft-reboot check: $msg"
    $checkForSoftReboot = $false
    $skipSoftRebootCheckReasons += $msg
}

if ($checkForSoftReboot -and ($vcrtIsUpdatedInstallConsistent -eq $true)) {
    # The soft-reboot case occurs when the installer returns ERROR_SUCCESS_REBOOT_REQUIRED (3010), 
    # but all files were actuall updated and the VCRT install is consistent. In this case, convert
    # the return code to NS_S_REBOOT_RECOMMENDED (862968) for soft reboot. This code is defined in
    # files nserror.h and zunenserror.h and can be identified by http://errors.
    Write-Host "Soft-reboot conditions detected, changing exit code from 3010 to 862968"
    $returnCode = 862968
} else {
    Write-Host "Reasons for skipping soft-reboot check:"
    Foreach ($reason in $skipSoftRebootCheckReasons) {
        Write-Host "  $reason"
    }
}

Write-Host "Wrapper Exit Code:  $returnCode"
Stop-Transcript
exit $returnCode

# SIG # Begin signature block
# MIIoLQYJKoZIhvcNAQcCoIIoHjCCKBoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAx/euVbHAt7uS2
# y4y9FWu1gZaSpY1rX8mHD7awv0bxnKCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
# esGEb+srAAAAAANOMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI5WhcNMjQwMzE0MTg0MzI5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDdCKiNI6IBFWuvJUmf6WdOJqZmIwYs5G7AJD5UbcL6tsC+EBPDbr36pFGo1bsU
# p53nRyFYnncoMg8FK0d8jLlw0lgexDDr7gicf2zOBFWqfv/nSLwzJFNP5W03DF/1
# 1oZ12rSFqGlm+O46cRjTDFBpMRCZZGddZlRBjivby0eI1VgTD1TvAdfBYQe82fhm
# WQkYR/lWmAK+vW/1+bO7jHaxXTNCxLIBW07F8PBjUcwFxxyfbe2mHB4h1L4U0Ofa
# +HX/aREQ7SqYZz59sXM2ySOfvYyIjnqSO80NGBaz5DvzIG88J0+BNhOu2jl6Dfcq
# jYQs1H/PMSQIK6E7lXDXSpXzAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUnMc7Zn/ukKBsBiWkwdNfsN5pdwAw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMDUxNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAD21v9pHoLdBSNlFAjmk
# mx4XxOZAPsVxxXbDyQv1+kGDe9XpgBnT1lXnx7JDpFMKBwAyIwdInmvhK9pGBa31
# TyeL3p7R2s0L8SABPPRJHAEk4NHpBXxHjm4TKjezAbSqqbgsy10Y7KApy+9UrKa2
# kGmsuASsk95PVm5vem7OmTs42vm0BJUU+JPQLg8Y/sdj3TtSfLYYZAaJwTAIgi7d
# hzn5hatLo7Dhz+4T+MrFd+6LUa2U3zr97QwzDthx+RP9/RZnur4inzSQsG5DCVIM
# pA1l2NWEA3KAca0tI2l6hQNYsaKL1kefdfHCrPxEry8onJjyGGv9YKoLv6AOO7Oh
# JEmbQlz/xksYG2N/JSOJ+QqYpGTEuYFYVWain7He6jgb41JbpOGKDdE/b+V2q/gX
# UgFe2gdwTpCDsvh8SMRoq1/BNXcr7iTAU38Vgr83iVtPYmFhZOVM0ULp/kKTVoir
# IpP2KCxT4OekOctt8grYnhJ16QMjmMv5o53hjNFXOxigkQWYzUO+6w50g0FAeFa8
# 5ugCCB6lXEk21FFB1FdIHpjSQf+LP/W2OV/HfhC3uTPgKbRtXo83TZYEudooyZ/A
# Vu08sibZ3MkGOJORLERNwKm2G7oqdOv4Qj8Z0JrGgMzj46NFKAxkLSpE5oHQYP1H
# tPx1lPfD7iNSbJsP6LiUHXH1MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGg0wghoJAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIAKGXW1m/FvtQTRX2UsEuUN4
# cKx0ChRz0Hk4P5V3KXISMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAwC7E4kHkqwoZ2zKLvsktUSqNKIo2KDc8cPse3c5TP4rR5h7hWulNCxHl
# tJvvS7nGyQHSlxD7mjFpr72jsFrjJTPxRsn2iTj7vyc5dxIXH4b0tRh0Ckrh8xL5
# 2ueJd50HhVxkbqgVLz/z65uIRkgvCbqr+Mg5K0XNZYcmifU6J5JWQ7U15I5VRY2h
# ewp8RvxTIU8IkRoX4hvMhpVFRM02D7TASV7ScI5MKWkIcV5Nw0ZuOGCPGcDOFVno
# hn0qq6tYg1DzdH+A23FwVuh/q0Z6LLXvapHK7klefNuAvEotiwgkCcdhB3FWIJ3Z
# Z3C+Og5pEUliUx29xn8Lcw7y20PVmqGCF5cwgheTBgorBgEEAYI3AwMBMYIXgzCC
# F38GCSqGSIb3DQEHAqCCF3AwghdsAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCCgTLhkqCw3Q7MCR/qSDGJjvev2MVGdQInSSbIoNV0qZQIGZNT7/Sd6
# GBMyMDIzMDgzMDA0NDYzMS4yNTlaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046OTYwMC0w
# NUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghHtMIIHIDCCBQigAwIBAgITMwAAAdj8SzOlHdiFFQABAAAB2DANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMzA1MjUxOTEy
# NDBaFw0yNDAyMDExOTEyNDBaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046OTYwMC0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDNeOsp0fXgAz7GUF0N+/0EHcQFri6wliTbmQNmFm8D
# i0CeQ8n4bd2td5tbtzTsEk7dY2/nmWY9kqEvavbdYRbNc+Esv8Nfv6MMImH9tCr5
# Kxs254MQ0jmpRucrm3uHW421Cfva0hNQEKN1NS0rad1U/ZOme+V/QeSdWKofCThx
# f/fsTeR41WbqUNAJN/ml3sbOH8aLhXyTHG7sVt/WUSLpT0fLlNXYGRXzavJ1qUOe
# Pzyj86hiKyzQJLTjKr7GpTGFySiIcMW/nyK6NK7Rjfy1ofLdRvvtHIdJvpmPSze3
# CH/PYFU21TqhIhZ1+AS7RlDo18MSDGPHpTCWwo7lgtY1pY6RvPIguF3rbdtvhoyj
# n5mPbs5pgjGO83odBNP7IlKAj4BbHUXeHit3Da2g7A4jicKrLMjo6sGeetJoeKoo
# j5iNTXbDwLKM9HlUdXZSz62ftCZVuK9FBgkAO9MRN2pqBnptBGfllm+21FLk6E3v
# VXMGHB5eOgFfAy84XlIieycQArIDsEm92KHIFOGOgZlWxe69leXvMHjYJlpo2VVM
# tLwXLd3tjS/173ouGMRaiLInLm4oIgqDtjUIqvwYQUh3RN6wwdF75nOmrpr8wRw1
# n/BKWQ5mhQxaMBqqvkbuu1sLeSMPv2PMZIddXPbiOvAxadqPkBcMPUBmrySYoLTx
# wwIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFPbTj0x8PZBLYn0MZBI6nGh5qIlWMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQD
# AgeAMA0GCSqGSIb3DQEBCwUAA4ICAQCunA6aSP48oJ1VD+SMF1/7SFiTGD6zyLC3
# Ju9HtLjqYYq1FJWUx10I5XqU0alcXTUFUoUIUPSvfeX/dX0MgofUG+cOXdokaHHS
# lo6PZIDXnUClpkRix9xCN37yFBpcwGLzEZlDKJb2gDq/FBGC8snTlBSEOBjV0eE8
# ICVUkOJzIAttExaeQWJ5SerUr63nq6X7PmQvk1OLFl3FJoW4+5zKqriY/PKGssOa
# A5ZjBZEyU+o7+P3icL/wZ0G3ymlT+Ea4h9f3q5aVdGVBdshYa/SehGmnUvGMA8j5
# Ct24inx+bVOuF/E/2LjIp+mEary5mOTrANVKLym2kW3eQxF/I9cj87xndiYH55Xf
# rWMk9bsRToxOpRb9EpbCB5cSyKNvxQ8D00qd2TndVEJFpgyBHQJS/XEK5poeJZ5q
# gmCFAj4VUPB/dPXHdTm1QXJI3cO7DRyPUZAYMwQ3KhPlM2hP2OfBJIr/VsDsh3sz
# LL2ZJuerjshhxYGVboMud9aNoRjlz1Mcn4iEota4tam24FxDyHrqFm6EUQu/pDYE
# DquuvQFGb5glIck4rKqBnRlrRoiRj0qdhO3nootVg/1SP0zTLC1RrxjuTEVe3PKr
# ETbtvcODoGh912Xrtf4wbMwpra8jYszzr3pf0905zzL8b8n8kuMBChBYfFds916K
# Tjc4TGNU9TCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZI
# hvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# MjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAy
# MDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25Phdg
# M/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPF
# dvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6
# GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBp
# Dco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50Zu
# yjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3E
# XzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0
# lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1q
# GFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ
# +QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PA
# PBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkw
# EgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxG
# NSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARV
# MFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAK
# BggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMC
# AYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvX
# zpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20v
# cGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYI
# KwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG
# 9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0x
# M7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmC
# VgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449
# xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wM
# nosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDS
# PeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2d
# Y3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxn
# GSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+Crvs
# QWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokL
# jzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL
# 6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggNQ
# MIICOAIBATCB+aGB0aSBzjCByzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEn
# MCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjk2MDAtMDVFMC1EOTQ3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBI
# p++xUJ+f85VrnbzdkRMSpBmvL6CBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA6Jku8zAiGA8yMDIzMDgzMDAyNTg1
# OVoYDzIwMjMwODMxMDI1ODU5WjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDomS7z
# AgEAMAoCAQACAgOLAgH/MAcCAQACAhOnMAoCBQDomoBzAgEAMDYGCisGAQQBhFkK
# BAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJ
# KoZIhvcNAQELBQADggEBABj88oy1sIE/gg9wKM4QXNb2FKzaXft1uboW1k7vK2B7
# 9Bm5dw/Lo7fVJ5FcFO8RdsVz+W79HXTabCFnGX9rn8EdkPuNPtKQ6xMyp19rWTk4
# ZFFEozWORO1yu3Jj6hprAkthqGftWODWYfHteDK7bMxta3G1omKPC3fNRtPehT+t
# 9BB967S25efKA8yrkKsylbSCMC+nCwoOJ7bBjFDoVq8Tbbphox9sWOZBdKxW7vAe
# MUSxX7+G6knKmiOih97Wo8l6jEVvwjtAPRmamC2YlnaoaQqOTf24rAiBvF4S9fmk
# 0ah+DABiypQLOpqq6eME1YMUXf2BE3rt/zT5NCShi00xggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAdj8SzOlHdiFFQABAAAB
# 2DANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCBA+Dda1Z9q0BbsyXgPGJZaL5qEoCBkFpmVo8u5IEwY
# 2zCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIDrjIX/8CZN3RTABMNt5u73M
# i3o3fmvq2j8Sik+2s75UMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAHY/EszpR3YhRUAAQAAAdgwIgQgxyo4zmUG+H1CN4Qe96KuiWXp
# SP6TWyfLJzMgCT0b3s8wDQYJKoZIhvcNAQELBQAEggIAO9/cd+m9abT1dgVRTQEK
# VDOPsDrcIuWSRW/htPUhC/bhAr+ejt8LBa+wtu5Hnml26TmHXRhgDz1/AUW42zYV
# 26fQnGfDGNXpCgGvXhzINDQIgxdCmSYHNkAHKrXJkn8gNl3tj4BxeZ5BNOk1acba
# +u4WU1J/Vfm3OkxkicaBc6rn0VgLGKA4OtarivDphxpdTWBumeIOC7svWytsYf/2
# yYjM5Na7QQH3x5AT7zXAPIuNjxSKFu5/wi8BAKdXhbV10lBPS/WrAmzRX+Wohq1W
# BZyHs0ZwSYUnx52x4vVXdk11w7hsI47zo5QNcMFx4+ryfQbtTgQilFvow5durqYX
# hk8zdfgKh5NzWVJzDGYpQXJ+Gg8hIjox/r8pjfPnt5a3WC2at4Suj58R/MqLEjSZ
# Yfc4F/0CT6quCvpnUgrWrWTed2PIWUHn0zSLeJ/a+vOBGehBX3JzA7neozxj9dkf
# 0LCTxPZZBdVH3Qiu8cfrY05GZVnOFpgBarXnA7rODwaEA7PFl6oqXsi3nymwWfZe
# Dy8lAG6y7itGaPnI/j4r5mQit40x2nwv6JYlF9OgRuxFYqESuTnAjXE4DM0lfiXq
# ph78LTMjlk0+/qG8qPYMR5JM83Jw3s4T8oYKOG5IoLy1gzC7QhfOvks9CUKES/69
# BaQBuCTGAirSiQpYoEU9L4w=
# SIG # End signature block
