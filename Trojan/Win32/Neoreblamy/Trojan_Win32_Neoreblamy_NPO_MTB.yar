
rule Trojan_Win32_Neoreblamy_NPO_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 58 d1 e0 8b 84 05 ?? ff ff ff 39 45 } //2
		$a_01_1 = {eb 07 8b 45 e4 48 89 45 e4 83 7d e4 f6 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}