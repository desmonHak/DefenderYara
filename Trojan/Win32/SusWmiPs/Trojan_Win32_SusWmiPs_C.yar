
rule Trojan_Win32_SusWmiPs_C{
	meta:
		description = "Trojan:Win32/SusWmiPs.C,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 } //powershell.exe -c  1
		$a_80_1 = {47 65 74 2d 57 6d 69 4f 62 6a 65 63 74 } //Get-WmiObject  1
		$a_80_2 = {77 69 6e 33 32 5f 70 68 79 73 69 63 61 6c 6d 65 6d 6f 72 79 } //win32_physicalmemory  1
		$a_00_3 = {36 00 39 00 38 00 30 00 32 00 63 00 39 00 38 00 2d 00 32 00 63 00 6a 00 32 00 2d 00 34 00 61 00 31 00 37 00 2d 00 39 00 38 00 77 00 30 00 2d 00 33 00 61 00 39 00 32 00 32 00 30 00 61 00 64 00 30 00 31 00 35 00 37 00 } //-1 69802c98-2cj2-4a17-98w0-3a9220ad0157
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*-1) >=3
 
}