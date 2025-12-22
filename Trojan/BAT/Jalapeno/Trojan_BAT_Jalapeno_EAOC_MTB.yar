
rule Trojan_BAT_Jalapeno_EAOC_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.EAOC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 06 06 06 5a d2 9c 06 17 58 0a 06 11 05 8e 69 fe 04 13 0d 11 0d 2d e7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}