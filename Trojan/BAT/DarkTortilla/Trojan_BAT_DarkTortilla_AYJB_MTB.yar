
rule Trojan_BAT_DarkTortilla_AYJB_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AYJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 06 1c 5b 1c d8 da 16 fe 01 13 09 11 09 2c 0d 02 06 02 06 91 20 b2 00 00 00 61 9c 00 00 06 17 d6 0a 00 06 07 fe 04 13 0a 11 0a 2d d3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}