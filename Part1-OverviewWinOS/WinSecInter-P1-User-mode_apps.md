## Win32 and the User-Mode Windows APIs

Loading a New Library

	# Import lib
	PS> $lib = Import-Win32Module -Path "kernel32.dll"
	
	# Print Exported funcs
	PS> Get-Win32ModuleExport -Module $lib
	PS> "{0:X}" -f (Get-Win32ModuleExport -Module $lib -ProcAddress "AllocConsole")
	
Viewing Imported APIs

	PS> Get-Win32ModuleImport -Path "kernel32.dll"
	PS> Get-Win32ModuleImport -Path "kernel32.dll" -DllName "ntdll.dll" | Where-Object Name -Match "^Nt"

> Use `-ResolveApiSet` to resolve API sets

Listing KnownDlls

	ls NtObject:\KnownDlls
	
## The Win32 GUI

Displaying all the current window stations and desktops

	PS> Get-NtWindowStationName
	PS> Get-NtWindowStationName -Current
	PS> Get-NtDesktopName
	PS> Get-NtDesktopName -Current
	
Enumerating windows for the current desktop

	PS> $desktop = Get-NtDesktop -Current
	PS> Get-NtWindow -Desktop $desktop

Sending the WM_GETTEXT message to all windows on the desktop

	PS> $ws = Get-NtWindow
	PS> $char_count = 2048
	PS> $buf = New-Win32MemoryBuffer -Length ($char_count*
	PS> foreach($w in $ws) {
		$len = Send-NtWindowMessage -Window $w -Message 0xD
		$buf.DangerousGetHandle() -WParam $char_count -Wait 
		$txt = $buf.ReadUnicodeString($len.ToInt32())
		if ($txt.Length -eq 0) {
			continue
		}
		"PID: $($w.ProcessId) - $txt"
	}
	PID: 10064 - System tray overflow window.
	PID: 16168 - HardwareMonitorWindow
	PID: 10064 - Battery Meter
	--snip--
	
Console Sessions

	# Displaying the processes in each console session using Get-NtProcess
	Get-NtProcess -InfoOnly | Group-Object SessionId
	
	# The contents of a session’s BNO directory
	ls NtObjectSession:\ | Group-Object TypeName
	
## Win32 Registy Paths

	PS> Use-NtObject($key = Get-NtKey \REGISTRY\MACHINE\SOFTWARE) {
		$key.Win32Path
	}
	HKEY_LOCAL_MACHINE\SOFTWARE
	
	PS> Use-NtObject($key = Get-NtKey -Win32Path "HKCU\SOFTWARE") {
		$key.FullPath
	}
	\REGISTRY\USER\S-1-5-21-818064985-378290696-2985406761-1002\SOFTWARE

Adding and accessing a registry key with a NUL character

	PS> $key = New-NtKey -Win32Path "HKCU\ABC`0XYZ"
	PS> Get-Item "NtKeyUser:\ABC`0XYZ"
	Name TypeName
	---- --------
	ABC XYZ Key
	PS> Get-Item "HKCU:\ABC`0XYZ"
	Get-Item : Cannot find path 'HKCU:\ABC XYZ' because it does not exist.
	PS> Remove-NtKey $key
	PS> $key.Close()
	
## DOS Device Paths

Displaying the symbolic links for the C: and Z: drives

	PS> Use-NtObject($cdrive = Get-NtSymbolicLink "\??\C:") {
		$cdrive | Select-Object FullPath, Target
	}
	FullPath Target
	-------- ------
	\GLOBAL??\C: \Device\HarddiskVolume3
	
	PS> Add-DosDevice Z: C:\Windows
	PS> Use-NtObject($zdrive = Get-NtSymbolicLink "\??\Z:") {
		$zdrive | Select-Object FullPath, Target
	}
	FullPath Target
	-------- ------
	\Sessions\0\DosDevices\00000000-011b224b\Z: \??\C:\windows
	PS> Remove-DosDevice Z:
	
Examples of Win32 filepath conversion

	PS> Set-Location $env:SystemRoot
	PS C:\Windows> Get-NtFilePathType "."
	Relative
	PS C:\Windows> Get-NtFilePath "."
	\??\C:\Windows
	PS C:\Windows> Get-NtFilePath "..\"
	\??\C:\
	PS C:\Windows> Get-NtFilePathType "C:ABC"
	DriveRelative
	PS C:\Windows> Get-NtFilePath "C:ABC"
	\??\C:\Windows\ABC
	PS C:\Windows> Get-NtFilePathType "\\?\C:\abc/..\xyz"
	LocalDevice
	PS C:\Windows> Get-NtFilePath "\\?\C:\abc/..\xyz"
	\??\C:\abc/..\xyz
	
Checking and testing long, path-aware applications

	PS> $path = "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem"
	PS> Get-NtKeyValue -Win32Path $path -Name "LongPathsEnabled"
	Name Type DataObject
	---- ---- ----------
	LongPathsEnabled Dword 1
	
	PS> (Get-Process -Id $pid).Path | Get-Win32ModuleManifest |
	Select-Object LongPathAware
	LongPathAware
	-------------
	True
	
	PS> $path = "C:\$('A'*300)"
	PS> $path.Length
	303
	PS> Get-NtFilePath -Path $path
	\??\C:\AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...

## Process Creation

Create Process with Win32

	PS> $proc = New-Win32Process

Start process with Verb - Shell API
	
	PS> Start-Process "test.txt" -Verb "print"
	
## System processes

Displaying all services using Get-Win32Service

	PS> Get-Win32Service
	
## Worked Examples

Finding Executables That Import Specific APIs

	PS> $imps = ls "$env:WinDir\*.exe" | ForEach-Object {
		Get-Win32ModuleImport -Path $_.FullName
	}
	PS> $imps | Where-Object Names -Contains "CreateProcessW" | Select-Object ModulePath
	ModulePath
	----------
	C:\WINDOWS\explorer.exe
	C:\WINDOWS\unins000.exe
	
Finding hidden registry keys (has NULL character in the name of it)

	PS> $key = New-NtKey -Win32Path "HKCU\SOFTWARE\`0HIDDENKEY"
	PS> ls NtKeyUser:\SOFTWARE -Recurse | Where-Object Name -Match "`0"
	Name TypeName
	---- --------
	SOFTWARE\ HIDDENKEY Key
	PS> Remove-NtKey $key
	PS> $key.Close()
	
Finding hidden registry values

	PS> $key = New-NtKey -Win32Path "HKCU\SOFTWARE\ABC"
	PS> Set-NtKeyValue -Key $key -Name "`0HIDDEN" -String "HELLO"
	PS> function Select-HiddenValue {
		[CmdletBinding()]
		param(
		[parameter(ValueFromPipeline)]
		$Key
		)
		Process {
		foreach($val in $Key.Values) {
			if ($val.Name -match "`0") {
				[PSCustomObject]@{
					RelativePath = $Key.RelativePath
					Name = $val.Name
					Value = $val.DataObject
				}
			}
		}
	}
	}
	PS> ls -Recurse NtKeyUser:\SOFTWARE | Select-HiddenValue | Format-Table
	RelativePath Name Value
	------------ ---- -----
	SOFTWARE\ABC HIDDEN HELLO
	PS> Remove-NtKey $key
	PS> $key.Close()
