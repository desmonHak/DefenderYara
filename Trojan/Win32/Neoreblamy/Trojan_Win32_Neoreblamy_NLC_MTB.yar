
rule Trojan_Win32_Neoreblamy_NLC_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NLC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 45 e0 83 7d e0 03 7c e9 89 4d e0 eb 11 8b 45 e0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}