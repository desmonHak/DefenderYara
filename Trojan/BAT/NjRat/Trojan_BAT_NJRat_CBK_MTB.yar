
rule Trojan_BAT_NJRat_CBK_MTB{
	meta:
		description = "Trojan:BAT/NJRat.CBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 04 18 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 03 08 6f ?? 00 00 0a 28 ?? 00 00 0a 6a 61 b7 28 ?? 00 00 0a 28 ?? 00 00 0a 13 05 07 11 05 6f ?? 00 00 0a 26 08 03 6f ?? 00 00 0a 17 da fe 01 13 06 11 06 2c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}