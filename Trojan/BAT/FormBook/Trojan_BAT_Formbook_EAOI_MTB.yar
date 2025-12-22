
rule Trojan_BAT_Formbook_EAOI_MTB{
	meta:
		description = "Trojan:BAT/Formbook.EAOI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 07 17 58 1f 25 5a 11 0a 17 58 1f 65 5a 61 07 61 13 0b 11 0b 11 09 ?? ?? ?? ?? ?? ?? ?? ?? ?? 5a 69 61 13 0b 02 11 07 11 0a ?? ?? ?? ?? ?? 13 0c 04 03 ?? ?? ?? ?? ?? 59 13 0d 11 0d 13 0e 11 0e 19 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}