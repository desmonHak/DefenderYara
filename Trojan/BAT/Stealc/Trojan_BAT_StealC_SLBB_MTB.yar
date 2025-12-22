
rule Trojan_BAT_StealC_SLBB_MTB{
	meta:
		description = "Trojan:BAT/StealC.SLBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 1c 28 14 00 00 0a 09 28 07 00 00 06 11 04 28 07 00 00 06 28 15 00 00 0a 6f 16 00 00 0a 28 04 00 00 06 09 08 28 05 00 00 06 73 17 00 00 0a 25 72 d1 00 00 70 6f 18 00 00 0a 25 72 e1 00 00 70 09 72 fd 00 00 70 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}