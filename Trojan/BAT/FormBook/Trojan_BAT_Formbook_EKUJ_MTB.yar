
rule Trojan_BAT_Formbook_EKUJ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.EKUJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 11 0f 20 86 00 00 00 91 13 0e 2b 9f 05 ?? ?? ?? ?? ?? 61 02 61 0a ?? ?? ?? ?? ?? 0c 08 ?? ?? ?? ?? ?? 25 06 93 0b 06 18 58 93 07 61 0b 1f 09 13 0e } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}