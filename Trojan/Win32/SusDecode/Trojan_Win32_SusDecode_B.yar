
rule Trojan_Win32_SusDecode_B{
	meta:
		description = "Trojan:Win32/SusDecode.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 } //powershell.exe -c  1
		$a_80_1 = {6d 6b 64 69 72 } //mkdir  1
		$a_80_2 = {6b 77 6f 72 6b 69 6e 67 } //kworking  1
		$a_80_3 = {63 65 72 74 2e 65 78 65 20 2d 64 65 63 6f 64 65 } //cert.exe -decode  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=3
 
}