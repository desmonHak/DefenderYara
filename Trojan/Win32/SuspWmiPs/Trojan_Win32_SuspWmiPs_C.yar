
rule Trojan_Win32_SuspWmiPs_C{
	meta:
		description = "Trojan:Win32/SuspWmiPs.C,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 } //powershell.exe -c  1
		$a_80_1 = {47 65 74 2d 57 6d 69 4f 62 6a 65 63 74 } //Get-WmiObject  1
		$a_80_2 = {77 69 6e 33 32 5f 70 68 79 73 69 63 61 6c 6d 65 6d 6f 72 79 } //win32_physicalmemory  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}