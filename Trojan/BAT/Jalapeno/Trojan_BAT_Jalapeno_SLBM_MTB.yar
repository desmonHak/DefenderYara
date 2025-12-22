
rule Trojan_BAT_Jalapeno_SLBM_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.SLBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 23 28 18 00 00 0a 72 0d 00 00 70 28 19 00 00 0a 0a 1f 23 28 18 00 00 0a 72 39 00 00 70 28 19 00 00 0a 0b 06 28 1a 00 00 0a 0c 08 2d 17 00 06 28 09 00 00 06 28 1b 00 00 0a 00 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}