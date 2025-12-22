
rule Trojan_BAT_Formbook_ZWK_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ZWK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 0e 04 0e 05 6f ?? 00 00 0a 0b 02 04 02 07 72 d1 09 00 70 28 ?? 00 00 06 05 0e 04 0e 05 07 72 d1 09 00 70 0e 06 28 ?? 00 00 06 02 04 02 07 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}