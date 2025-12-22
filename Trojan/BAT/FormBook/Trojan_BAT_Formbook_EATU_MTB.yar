
rule Trojan_BAT_Formbook_EATU_MTB{
	meta:
		description = "Trojan:BAT/Formbook.EATU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 0e 04 11 07 ?? ?? ?? ?? ?? 05 69 61 13 08 11 04 11 08 ?? ?? ?? ?? ?? 00 0e 05 2c 09 11 08 19 5d 16 fe 01 2b 01 16 13 09 11 09 2c 12 00 08 11 08 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? 5a 58 0c 00 00 11 07 17 58 13 07 11 07 0e 04 ?? ?? ?? ?? ?? fe 04 13 0a 11 0a 2d a9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}