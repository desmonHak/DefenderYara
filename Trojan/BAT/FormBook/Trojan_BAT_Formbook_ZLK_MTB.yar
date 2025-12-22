
rule Trojan_BAT_Formbook_ZLK_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ZLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 06 93 0b 06 18 58 93 07 61 0b 11 0f 20 b3 00 00 00 93 20 86 5e 00 00 59 13 0e 38 ?? ff ff ff 7e ?? 00 00 04 74 ?? 00 00 1b 07 9a 25 0d 2c 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}