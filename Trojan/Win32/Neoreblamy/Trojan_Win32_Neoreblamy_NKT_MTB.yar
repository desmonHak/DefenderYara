
rule Trojan_Win32_Neoreblamy_NKT_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NKT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 24 58 6b c0 00 8d 84 05 20 fd ff ff 6a 04 59 } //1
		$a_01_1 = {eb 07 8b 45 e0 40 89 45 e0 83 7d e0 01 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}