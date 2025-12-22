
rule Trojan_BAT_Formbook_PGDT_MTB{
	meta:
		description = "Trojan:BAT/Formbook.PGDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 6f ?? 00 00 0a 13 04 04 03 6f ?? 00 00 0a 59 13 05 03 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 11 05 17 59 25 13 05 16 31 32 03 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 11 05 17 59 25 13 05 16 31 1b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}