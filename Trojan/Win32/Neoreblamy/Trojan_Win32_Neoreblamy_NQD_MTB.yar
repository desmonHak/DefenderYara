
rule Trojan_Win32_Neoreblamy_NQD_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NQD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 14 58 d1 e0 8d 84 05 ?? ?? ff ff 6a 04 } //1
		$a_01_1 = {8b 45 e8 40 89 45 e8 83 7d e8 04 7d 10 8b 45 e8 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}