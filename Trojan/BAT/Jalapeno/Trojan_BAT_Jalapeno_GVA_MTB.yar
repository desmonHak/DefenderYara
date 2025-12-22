
rule Trojan_BAT_Jalapeno_GVA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 16 13 09 2b 1a 00 08 11 09 08 11 09 91 07 11 09 07 8e 69 5d 91 61 d2 9c 00 11 09 17 58 13 09 11 09 08 8e 69 fe 04 13 0a 11 0a 2d d9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}