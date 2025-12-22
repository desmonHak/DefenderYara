
rule Trojan_Win32_Neoreblamy_NQT_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NQT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 65 e0 00 eb 07 8b 45 e0 40 89 45 e0 } //1
		$a_03_1 = {5a 6b d2 07 8d 94 15 ?? ?? ff ff 89 04 0a } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}