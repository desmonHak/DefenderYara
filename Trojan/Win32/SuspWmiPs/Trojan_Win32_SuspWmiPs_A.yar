
rule Trojan_Win32_SuspWmiPs_A{
	meta:
		description = "Trojan:Win32/SuspWmiPs.A,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 } //powershell.exe -c  1
		$a_80_1 = {47 65 74 2d 57 6d 69 4f 62 6a 65 63 74 } //Get-WmiObject  1
		$a_80_2 = {2d 43 6c 61 73 73 4e 61 6d 65 } //-ClassName  1
		$a_80_3 = {57 69 6e 33 32 5f 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d } //Win32_OperatingSystem  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}