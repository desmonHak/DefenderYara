
rule Trojan_Win32_Neoreblamy_NPG_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e4 40 89 45 e4 83 7d e4 01 7d 0d 8b 45 e4 } //1
		$a_01_1 = {6a 04 58 6b c0 00 8b 44 05 e0 40 6a 04 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}