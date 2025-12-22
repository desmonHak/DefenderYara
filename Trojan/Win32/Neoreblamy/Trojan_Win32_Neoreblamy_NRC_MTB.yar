
rule Trojan_Win32_Neoreblamy_NRC_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NRC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {7d 3f 83 65 e4 ?? eb 07 8b 45 e4 40 89 45 e4 } //1
		$a_03_1 = {8b 45 94 40 89 45 94 83 7d 94 ?? 7d 10 8b 45 94 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}