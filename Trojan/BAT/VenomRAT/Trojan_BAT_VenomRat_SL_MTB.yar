
rule Trojan_BAT_VenomRat_SL_MTB{
	meta:
		description = "Trojan:BAT/VenomRat.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 09 8f 06 00 00 01 25 71 06 00 00 01 20 aa 00 00 00 61 d2 81 06 00 00 01 09 17 58 0d 09 06 8e 69 fe 04 13 0b 11 0b 2d d7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}