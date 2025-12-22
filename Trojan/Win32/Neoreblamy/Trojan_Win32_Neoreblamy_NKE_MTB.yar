
rule Trojan_Win32_Neoreblamy_NKE_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 c0 40 89 45 c0 83 7d c0 02 7d 10 8b 45 c0 } //1
		$a_03_1 = {6a 04 58 d1 e0 8b 84 05 ?? ?? ff ff 40 6a 04 59 d1 e1 89 84 0d ?? ?? ff ff 6a 04 58 d1 e0 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}