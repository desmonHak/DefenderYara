
rule Trojan_Win32_Neoreblamy_NQP_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NQP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e0 40 89 45 e0 83 7d e0 01 7d 10 8b 45 e0 } //1
		$a_03_1 = {59 c1 e1 00 8d 8c 0d ?? ?? ff ff 6a 04 5a } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}