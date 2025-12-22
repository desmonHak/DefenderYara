
rule Trojan_BAT_Formbook_ZQL_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ZQL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 7b 29 00 00 04 6f ?? 00 00 0a 18 03 59 1e 5a 1f 1f 5f 63 20 ff 00 00 00 5f d2 2a } //6
		$a_03_1 = {25 2d 16 26 02 02 fe 06 0f 01 00 06 73 ?? 00 00 0a 25 0b 7d ?? 00 00 04 07 28 ?? 00 00 2b 06 fe 06 13 01 00 06 } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}