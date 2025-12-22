
rule Trojan_Win32_ClickFix_HHM_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.HHM!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 00 74 00 61 00 72 00 74 00 2d 00 42 00 69 00 74 00 73 00 54 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 20 00 27 00 68 00 74 00 74 00 70 00 } //1 Start-BitsTransfer 'http
		$a_00_1 = {3b 00 20 00 53 00 74 00 61 00 72 00 74 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 } //1 ; Start-Process mshta.exe
		$a_00_2 = {61 00 70 00 70 00 64 00 61 00 74 00 61 00 } //1 appdata
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}