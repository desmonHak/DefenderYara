
rule Trojan_Win32_SuspProxi_B{
	meta:
		description = "Trojan:Win32/SuspProxi.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_80_0 = {6d 73 68 74 61 2e 65 78 65 } //mshta.exe  1
		$a_80_1 = {70 75 62 6c 69 63 } //public  1
		$a_80_2 = {74 65 78 74 62 6f 78 4e 61 6d 65 4e 61 6d 65 73 70 61 63 65 2e 68 74 61 } //textboxNameNamespace.hta  1
		$a_80_3 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_4 = {73 74 61 72 74 2e 68 74 61 } //start.hta  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=3
 
}