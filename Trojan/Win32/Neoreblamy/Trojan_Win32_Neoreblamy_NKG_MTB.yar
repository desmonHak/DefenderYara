
rule Trojan_Win32_Neoreblamy_NKG_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NKG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 e0 40 89 45 e0 83 7d e0 02 7d 10 8b 45 e0 } //1
		$a_03_1 = {6a 04 58 c1 e0 00 83 bc 05 ?? ?? ff ff 00 75 19 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}