
rule Trojan_Win32_ClickFix_IIP_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.IIP!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6e 00 75 00 6c 00 26 00 63 00 75 00 72 00 6c 00 20 00 2d 00 } //1 nul&curl -
		$a_00_1 = {63 00 6d 00 64 00 3e 00 6e 00 75 00 6c 00 } //1 cmd>nul
		$a_00_2 = {65 00 6e 00 63 00 6f 00 64 00 65 00 3d 00 } //1 encode=
		$a_00_3 = {64 00 65 00 6c 00 20 00 2f 00 71 00 20 00 } //1 del /q 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule Trojan_Win32_ClickFix_IIP_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.IIP!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6e 00 65 00 74 00 73 00 68 00 20 00 77 00 6c 00 61 00 6e 00 20 00 73 00 68 00 6f 00 77 00 20 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 73 00 } //1 netsh wlan show profiles
		$a_00_1 = {20 00 2d 00 73 00 70 00 6c 00 69 00 74 00 } //1  -split
		$a_00_2 = {2d 00 4d 00 65 00 74 00 68 00 6f 00 64 00 20 00 50 00 4f 00 53 00 54 00 20 00 2d 00 62 00 6f 00 64 00 79 00 20 00 28 00 20 00 2d 00 6a 00 6f 00 69 00 6e 00 } //1 -Method POST -body ( -join
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}