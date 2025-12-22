
rule Trojan_BAT_VenomRAT_EHLH_MTB{
	meta:
		description = "Trojan:BAT/VenomRAT.EHLH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 04 8f 06 00 00 01 25 71 06 00 00 01 09 61 d2 81 06 00 00 01 11 04 17 58 13 04 11 04 06 8e 69 fe 04 13 ?? ?? ?? 2d d7 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}