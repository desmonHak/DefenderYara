
rule Trojan_Win32_Neoreblamy_NPE_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 58 d1 e0 8b 44 05 ?? 40 6a 04 59 } //1
		$a_01_1 = {eb 07 8b 45 e0 48 89 45 e0 83 7d e0 eb } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}