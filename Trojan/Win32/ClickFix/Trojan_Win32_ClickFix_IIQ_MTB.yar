
rule Trojan_Win32_ClickFix_IIQ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.IIQ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2d 00 6a 00 6f 00 69 00 6e 00 28 00 24 00 7b 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 } //1 -join(${env:temp
		$a_00_1 = {28 00 2d 00 6a 00 6f 00 69 00 6e 00 28 00 28 00 2d 00 6a 00 6f 00 69 00 6e 00 28 00 } //1 (-join((-join(
		$a_02_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 2d 00 6a 00 6f 00 69 00 6e 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}