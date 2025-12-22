
rule Trojan_BAT_Bladabindi_SLKS_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.SLKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 43 01 00 06 28 c2 04 00 06 13 04 11 04 28 6a 00 00 0a 13 05 28 44 01 00 06 28 68 00 00 0a 28 45 01 00 06 28 69 00 00 0a 11 05 28 6b 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}