
rule Trojan_BAT_Formbook_ZPL_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ZPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 7b 64 00 00 04 7b ?? 00 00 04 02 7b ?? 00 00 04 03 6f ?? 00 00 0a 0a 12 00 28 ?? 00 00 0a 02 7b ?? 00 00 04 7b ?? 00 00 04 02 7b ?? 00 00 04 7b 5f 00 00 04 6f ?? 00 00 0a 59 73 ?? 00 00 0a 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}