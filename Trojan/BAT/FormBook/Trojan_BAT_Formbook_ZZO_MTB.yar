
rule Trojan_BAT_Formbook_ZZO_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ZZO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 07 11 17 1f 1f 5a 11 18 1d 5a 58 61 13 19 02 11 17 11 18 6f ?? 00 00 0a 13 1a 04 03 6f ?? 00 00 0a 59 13 1b 11 1b 13 1c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}