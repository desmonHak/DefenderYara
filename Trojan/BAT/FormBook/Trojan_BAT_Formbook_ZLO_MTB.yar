
rule Trojan_BAT_Formbook_ZLO_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ZLO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 12 20 cb 03 00 00 5a 11 0f 20 f5 03 00 00 5a 61 20 ff 03 00 00 5f 13 13 06 11 13 1b 63 94 17 11 13 1f 1f 5f 1f 1f 5f 62 5f 16 fe 03 13 14 02 11 0f 11 12 6f ?? 00 00 0a 13 15 04 03 6f ?? 00 00 0a 59 13 16 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}