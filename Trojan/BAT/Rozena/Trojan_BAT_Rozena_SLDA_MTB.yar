
rule Trojan_BAT_Rozena_SLDA_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SLDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 17 00 00 04 28 27 00 00 06 28 01 00 00 06 0a 06 20 3a 0b 11 8c 28 03 00 00 06 28 05 00 00 2b 80 02 00 00 04 06 20 d4 c3 b2 a1 28 03 00 00 06 28 06 00 00 2b 80 03 00 00 04 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}