
rule Trojan_Win32_Neoreblamy_NRF_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NRF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7d 37 83 65 e0 00 eb 07 8b 45 e0 40 89 45 e0 } //1
		$a_01_1 = {50 83 65 f4 00 eb 07 8b 45 f4 40 89 45 f4 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}