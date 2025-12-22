
rule Trojan_BAT_Formbook_ZHK_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ZHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 07 11 08 6f ?? 00 00 0a 13 09 03 06 6f ?? 00 00 0a 59 13 0a 11 0a 11 04 61 16 2f 0a 03 06 6f ?? 00 00 0a 59 13 0a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}