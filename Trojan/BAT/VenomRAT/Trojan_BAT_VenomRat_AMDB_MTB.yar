
rule Trojan_BAT_VenomRat_AMDB_MTB{
	meta:
		description = "Trojan:BAT/VenomRat.AMDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 09 11 0a 8f ?? 00 00 01 25 71 ?? 00 00 01 11 05 11 0a 11 05 8e 69 5d 91 61 d2 81 ?? 00 00 01 11 0a 17 58 13 0a 11 0a 11 09 8e 69 32 d2 } //5
		$a_03_1 = {0a 13 0c 11 0c 11 0b 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 0d 11 0d 11 09 16 11 09 8e 69 6f ?? 00 00 0a 11 0d 6f ?? 00 00 0a 11 0c 6f ?? 00 00 0a 13 09 de 0c } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}