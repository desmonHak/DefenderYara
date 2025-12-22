
rule Trojan_BAT_AveMaria_AWIB_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.AWIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 06 11 1f 6f ?? 00 00 0a 13 20 03 06 6f ?? 00 00 0a 59 13 21 06 12 20 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 21 17 59 25 13 21 16 fe 02 16 fe 01 13 23 11 23 2c 06 00 17 13 07 2b 57 06 12 20 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 21 17 59 25 13 21 16 fe 02 16 fe 01 13 24 11 24 2c 06 00 17 13 07 2b 30 06 12 20 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 11 1f 17 58 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}