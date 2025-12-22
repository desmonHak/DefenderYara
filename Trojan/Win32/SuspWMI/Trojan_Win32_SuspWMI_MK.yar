
rule Trojan_Win32_SuspWMI_MK{
	meta:
		description = "Trojan:Win32/SuspWMI.MK,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 } //powershell.exe -c  1
		$a_80_1 = {47 65 74 2d 57 6d 69 4f 62 6a 65 63 74 20 77 69 6e 33 32 5f 50 72 6f 63 65 73 73 6f 72 } //Get-WmiObject win32_Processor  1
		$a_80_2 = {53 65 6c 65 63 74 20 4e 75 6d 62 65 72 4f 66 43 6f 72 65 73 } //Select NumberOfCores  1
		$a_80_3 = {63 6d 64 2e 65 78 65 20 2f 63 } //cmd.exe /c  1
		$a_80_4 = {74 69 6d 65 6f 75 74 } //timeout  1
		$a_00_5 = {2f 00 54 00 } //1 /T
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_00_5  & 1)*1) >=3
 
}