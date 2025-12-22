
rule Trojan_BAT_Formbook_PGAF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.PGAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 8c 08 00 00 1b 03 04 6f ?? ?? 00 0a 0b 1e 13 05 38 5a ff ff ff 06 17 58 0a 0e 04 25 5a 0d 0e 04 09 58 0d 11 07 20 a3 01 00 00 93 20 2f 30 00 00 59 13 05 38 37 ff ff ff } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}