
rule Trojan_Win32_Neoreblamy_NPQ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 cc 40 89 45 cc 83 7d cc 02 7d 10 8b 45 cc } //1
		$a_01_1 = {eb 07 8b 45 dc 40 89 45 dc 83 7d dc 12 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}