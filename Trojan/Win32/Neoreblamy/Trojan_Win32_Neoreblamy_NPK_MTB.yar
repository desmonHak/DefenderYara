
rule Trojan_Win32_Neoreblamy_NPK_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 e0 40 89 45 e0 83 7d e0 01 7d 0d 8b 45 e0 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}