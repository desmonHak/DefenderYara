
rule Trojan_Win32_ClickFix_GGU_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.GGU!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 00 65 00 6e 00 64 00 4b 00 65 00 79 00 73 00 28 00 5b 00 63 00 68 00 61 00 72 00 5d 00 } //1 SendKeys([char]
		$a_00_1 = {57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 } //1 WScript.Shell
		$a_00_2 = {28 00 4e 00 65 00 77 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 2d 00 43 00 6f 00 6d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 } //1 (New-Object -ComObject
		$a_00_3 = {68 00 74 00 74 00 70 00 } //1 http
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}