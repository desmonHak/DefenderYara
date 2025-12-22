
rule Trojan_Win32_SuspWMI_C{
	meta:
		description = "Trojan:Win32/SuspWMI.C,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 09 00 00 "
		
	strings :
		$a_80_0 = {77 6d 69 63 2e 65 78 65 20 6f 73 20 67 65 74 } //wmic.exe os get  1
		$a_80_1 = {6c 61 73 74 62 6f 6f 74 75 70 74 69 6d 65 } //lastbootuptime  1
		$a_80_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2f 77 49 6e 64 } //powershell.exe /wInd  1
		$a_80_3 = {47 65 74 2d 57 6d 69 4f 62 6a 65 63 74 20 2d 43 6c 61 73 73 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d } //Get-WmiObject -Class Win32_ComputerSystem  1
		$a_80_4 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 77 69 6e 64 20 68 69 64 64 65 6e } //powershell.exe -wind hidden  1
		$a_80_5 = {63 6d 64 2e 65 78 65 20 2f 63 } //cmd.exe /c  1
		$a_80_6 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 73 74 61 72 74 75 70 5f 76 72 75 6e 2e 62 61 74 } //AppData\Local\Temp\startup_vrun.bat  1
		$a_80_7 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 } //powershell.exe -c  1
		$a_80_8 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 46 69 6c 65 50 61 74 68 } //Start-Process -WindowStyle hidden -FilePath  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=2
 
}