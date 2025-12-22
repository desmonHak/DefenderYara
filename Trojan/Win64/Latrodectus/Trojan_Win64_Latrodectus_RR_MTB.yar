
rule Trojan_Win64_Latrodectus_RR_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 30 14 0f 66 } //1
		$a_01_1 = {48 81 f9 01 92 01 00 0f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}