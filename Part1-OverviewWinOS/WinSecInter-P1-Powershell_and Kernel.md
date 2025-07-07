## Configuring PowerShell
Set the script execution policy

	PS> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force

> Remove `-Scope CurrentUser` for all users

Install Module - the PowerShell Gallery (https://www.powershellgallery.com)

	PS> Install-Module NtObjectManager -Scope CurrentUser -Force
	PS> Import-Module NtObjectManager
	PS> Update-Module NtObjectManager

Get Help
	
	PS> Get-Command -Name *SecurityDescriptor*
	
> Param: `-Parameter`, `-Examples`, `-ShowWindow`, `-Module`, `-Name`

	Get-Command -Module NtObjectManager -Name Start-*
	
New Alias

	PS> New-Alias -Name swt -Value Start-NtWait
	
Function & Script Block
	
	PS> function Get-NameValue {
	param(
		[string]$Name = "",
		$Value
	)
		return "We've got $Name with value $Value"
	}
	
	PS> Get-NameValue -Name "Hello" -Value "World"
	We've got Hello with value World
	
	PS> Get-NameValue "Goodbye" 12345
	We've got Goodbye with value 12345

	PS> $script = { Write-Output "Hello" }
	PS> & $script
	Hello

Displaying and Manipulating Objects

	PS> Get-Process | Select-Object Id, ProcessName
	PS> Get-Process | Get-Member -Type Property
	PS> Get-Process | Select-Object * | Out-GridView
	
Display
	
	Format-List
	Format-Table
	Out-Host -Paging
	Write-Host "Hello"
	Out-GridView
	
Filtering, Ordering, and Grouping Objects

	PS> Get-Process | Where-Object ProcessName -EQ "explorer"
	PS> Get-Process | Where-Object { $_.ProcessName -eq "explorer" }
	
> Where-Object = ?

> $_ is the current object in pipeline

| Operator   | Example                           | Description                                     |
|------------|-----------------------------------|-------------------------------------------------|
| -EQ        | ProcessName -EQ "explorer"        | Equal to the value                              |
| -NE        | ProcessName -NE "explorer"        | Not equal to the value                          |
| -Match     | ProcessName -Match "ex.*"         | Matches a string against a regular expression   |
| -NotMatch  | ProcessName -NotMatch "ex.*"      | Inverse of the -Match operator                  |
| -Like      | ProcessName -Like "ex*"           | Matches a string against a wildcard             |
| -NotLike   | ProcessName -NotLike "ex*"        | Inverse of the -Like operator                   |
| -GT        | ProcessName -GT "ex"              | Greater-than comparison                         |
| -LT        | ProcessName -LT "ex"              | Less-than comparison  

	PS> Get-Process | Sort-Object Handles -Descending
	PS> Get-Process | Group-Object ProcessName | Where-Object Count -GT 10 | Sort-Object Count

Exporting Data

	Out-File
	Get-Process > processes.txt
	Export-CliXml
	Export-Csv

## Security Reference Monitor

Query SID and invert of it
	
	Get-NtSid -Name "Users"
	Get-NtSid -Sddl "S-1-5-32-545"
  
## The Object Manager

Get Object Type of kernel
	
	Get-NtType
	
The Object Manager Namespace

	ls NtObject:\ | Sort-Object Name
	ls NtObject:\Dfs | Select-Object SymbolicLinkTarget
	
Nt Status

	Get-NtStatus 0xC0000034 | Format-List
	
Object Handle

	//Access Masks
	Get-NtType | Select-Object Name, GenericMapping
	Get-NtTypeAccess -Type File
	Get-NtTypeAccess -Type File | Select SDKName, Value
	
	Get-NtAccessMask -FileAccess ReadData, ReadAttributes, ReadControl
	Get-NtAccessMask -FileAccess GenericRead
	
	Get-NtAccessMask -FileAccess GenericRead -MapGenericRights
	Get-NtAccessMask 0x120089 -AsTypeAccess File
	
Duplicate Handle

	PS> $mut = New-NtMutant "\BaseNamedObjects\ABC"
	PS> $mut.GrantedAccess
	ModifyState, Delete, ReadControl, WriteDac, WriteOwner, Synchronize
	
	PS> Use-NtObject($dup = Copy-NtObject $mut) {
		$mut
		$dup
		Compare-NtObject $mut $dup
	}
	Handle Name NtTypeName Inherit ProtectFromClose
	------ ---- ---------- ------- ----------------
	1616 ABC Mutant False False
	2212 ABC Mutant False False
	True
	
	PS> $mask = Get-NtAccessMask -MutantAccess ModifyState
	PS> Use-NtObject($dup = Copy-NtObject $mut -DesiredAccessMask $mask) { 
		$dup.GrantedAccess
		Compare-NtObject $mut $dup
	}
	ModifyState
	True
	
Query and Set Information System Calls Enum

	PS> Get-NtObjectInformationClass Process
	PS> Get-NtObjectInformationClass Key -Set

## The Input/Output Manager

Displaying the Device objects

	ls NtObject:\Device

Opening a device object and displaying its volume path

	PS> Use-NtObject($f = Get-NtFile "\SystemRoot\notepad.exe") {
		$f | Select-Object FullPath, NtTypeName
	}
	FullPath NtTypeName
	-------- ----------
	\Device\HarddiskVolume3\Windows\notepad.exe File
	
	PS> Get-Item NtObject:\Device\HarddiskVolume3
	Name TypeName
	---- --------
	HarddiskVolume3 Device
	
Enumerating all loaded kernel drivers

	Get-NtKernelModule
	
## The Process and Thread Manager

Displaying processes and threads without high privilege

	PS> Get-NtProcess -InfoOnly
	PS> Get-NtThread -InfoOnly
	
Opening the current process by its process ID

	PS> $proc = Get-NtProcess -ProcessId $pid
	PS> $proc.CommandLine
	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
	
	PS> $proc.Win32ImagePath
	C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
	
## The Memory Manager

NtVirtualMemory Commands

	PS> Get-NtVirtualMemory

Performing various memory operations on a process

	# Allocate Memory
	PS> $addr = Add-NtVirtualMemory -Size 1000 -Protection ReadWrite
	PS> Get-NtVirtualMemory -Address $addr
	Address Size Protect Type State Name
	------- ---- ------- ---- ----- ----
	000002624A440000 4096 ReadWrite Private Commit
	
	# Write to mem
	PS> Read-NtVirtualMemory -Address $addr -Size 4 | Out-HexDump
	00 00 00 00
	PS> Write-NtVirtualMemory -Address $addr -Data @(1,2,3,4)
	4
	
	//Read from mem
	PS> Read-NtVirtualMemory -Address $addr -Size 4 | Out-HexDump
	01 02 03 04
	
	# Change Protection
	PS> Set-NtVirtualMemory -Address $addr -Protection ExecuteRead -Size 4
	ReadWrite
	
	PS> Get-NtVirtualMemory -Address $addr
	Address Size Protect Type State Name
	------- ---- ------- ---- ----- ----
	000002624A440000 4096 ExecuteRead Private Commit
	
	# Free mem
	PS> Remove-NtVirtualMemory -Address $addr
	PS> Get-NtVirtualMemory -Address $addr
	Address Size Protect Type State Name
	------- ---- ------- ---- ----- ----
	000002624A440000 196608 NoAccess None Free

Section Objects

	# Creating a section and mapping it into memory
	PS> $s = New-NtSection -Size 4096 -Protection ReadWrite
	PS> $m = Add-NtSection -Section $s -Protection ReadWrite
	PS> Get-NtVirtualMemory $m.BaseAddress
	Address Size Protect Type State Name
	------- ---- ------- ---- ----- ----
	000001C3DD0E0000 4096 ReadWrite Mapped Commit
	
	PS> Remove-NtSection -Mapping $m
	PS> Get-NtVirtualMemory -Address 0x1C3DD0E0000
	Address Size Protect Type State Name
	------- ---- ------- ---- ----- ----
	000001C3DD0E0000 4096 NoAccess None Free
	
	# Error case
	PS> Add-NtSection -Section $s -Protection ExecuteRead
	Exception calling "Map" with "9" argument(s):
	"(0xC000004E) - A view to a section specifies a protection
	incompatible with the initial view's protection."
	
Section Objects - Mapping notepad.exe and viewing the loaded image

	PS> $sect = New-NtSectionImage -Win32Path "C:\Windows\notepad.exe"
	PS> $map = Add-NtSection -Section $sect -Protection ReadOnly
	PS> Get-NtVirtualMemory -Address $map.BaseAddress
	Address Size Protect Type State Name
	------- ---- ------- ---- ----- ----
	00007FF667150000 4096 ReadOnly Image Commit notepad.exe
	
	PS> Get-NtVirtualMemory -Type Image -Name "notepad.exe"
	Address Size Protect Type State Name
	------- ---- ------- ---- ----- ----
	00007FF667150000 4096 ReadOnly Image Commit notepad.exe
	00007FF667151000 135168 ExecuteRead Image Commit notepad.exe
	
	PS> Out-HexDump -Buffer $map -ShowAscii -Length 128
	4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 - MZ..............
	B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 - ........@.......
	
## Code Integrity

Displaying the Authenticode signature for a kernel driver

	PS> Get-AuthenticodeSignature "$env:WinDir\system32\notepad.exe" | Format-List
	
## Advanced Local Procedure Call

Not yet

## The Configuration Manager

Enumerating the registry root key

	PS> ls NtObject:\REGISTRY
	
	# Opening a registry key and querying its values
	PS> $key = Get-NtKey \Registry\Machine\SOFTWARE\Microsoft\ .NETFramework
	PS> Get-NtKeyValue -Key $key

## Worked Examples

Finding Open Handles by Name

	PS> $hs = Get-NtHandle -ObjectType File | Where-Object Name -Match Windows
	PS> $hs | Select-Object ProcessId, Handle, Name
	
Finding Shared Objects
	
	# Finding shared Section handles
	PS> $ss = Get-NtHandle -ObjectType Section -GroupByAddress |
	Where-Object ShareCount -eq 2
	PS> $mask = Get-NtAccessMask -SectionAccess MapWrite
	PS> $ss = $ss | Where-Object { Test-NtAccessMask $_.AccessIntersection $mask }
	PS> foreach($s in $ss) {
		$count = ($s.ProcessIds | Where-Object {
			Test-NtProcess -ProcessId $_ -Access DupHandle
		}).Count
		if ($count -eq 1) {
			$s.Handles | Select ProcessId, ProcessName, Handle
		}
	}
	ProcessId ProcessName Handle
	--------- ----------- ------
	9100 Chrome.exe 4400
	4072 audiodg.exe 2560
	
Modifying a Mapped Section
	
	#Mapping and modifying a Section object
	PS> $sect = $handle.GetObject()
	PS> $map = Add-NtSection -Section $sect -Protection ReadWrite
	PS> $random = Get-RandomByte -Size $map.Length
	PS> Write-NtVirtualMemory -Mapping $map -Data $random
	4096
	
	PS> Out-HexDump -Buffer $map -Length 16 -ShowAddress -ShowHeader
	00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
	-----------------------------------------------------------------
	000001811C860000: DF 24 04 E1 AB 2A E1 76 EB 19 00 8D 79 28 9C BA
	
	# The section editor GUI
	Show-NtSection -Section $sect
	
Finding Writable and Executable Memory

	PS> $proc = Get-NtProcess -ProcessId $pid -Access QueryLimitedInformation
	PS> Get-NtVirtualMemory -Process $proc | Where-Object {
		$_.Protect -band "ExecuteReadWrite"
	}
	Address Size Protect Type State Name
	------- ---- ------- ---- ----- ----
	0000018176450000 4096 ExecuteReadWrite Private Commit
	0000018176490000 8192 ExecuteReadWrite Private Commit
	0000018176F60000 61440 ExecuteReadWrite Private Commit
	--snip--
	
	PS> $proc.Close()