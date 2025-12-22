
rule Trojan_Win32_ClaimLoader_GVB_MTB{
	meta:
		description = "Trojan:Win32/ClaimLoader.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c8 83 e1 03 8a 0c 8d ?? ?? ?? ?? 30 4c 04 68 40 3b c2 7c eb } //2
		$a_01_1 = {73 09 80 34 08 19 40 3b c2 72 f7 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}