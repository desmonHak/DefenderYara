
rule Trojan_BAT_Formbook_ZXQ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ZXQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 06 6f ?? 00 00 0a 13 0c 04 03 6f ?? 00 00 0a 59 0d 20 b7 50 a3 d9 28 ?? 00 00 06 0e 05 8c ?? 00 00 01 28 ?? 00 00 0a 13 04 11 04 20 88 50 a3 d9 28 ?? 00 00 06 6f ?? 00 00 0a 13 09 11 09 2c 05 07 1f 63 58 0b 03 12 0c 28 ?? 00 00 0a 6f ?? 00 00 0a 09 17 59 25 0d 16 fe 02 16 fe 01 13 0a 11 0a 2c 02 2b 41 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}