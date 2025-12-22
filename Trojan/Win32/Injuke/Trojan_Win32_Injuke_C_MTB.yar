
rule Trojan_Win32_Injuke_C_MTB{
	meta:
		description = "Trojan:Win32/Injuke.C!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2d 00 62 00 78 00 6f 00 72 00 } //1 -bxor
		$a_00_1 = {2e 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 } //1 .replace
		$a_00_2 = {62 00 61 00 73 00 65 00 36 00 34 00 } //1 base64
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}