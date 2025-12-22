
rule Trojan_Win32_Neoreblamy_NPX_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 d4 40 89 45 d4 83 7d d4 01 7d 13 } //1
		$a_03_1 = {6a 04 58 c1 e0 00 8b 84 05 ?? ?? ff ff 40 6a } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}