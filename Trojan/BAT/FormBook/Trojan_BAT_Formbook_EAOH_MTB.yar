
rule Trojan_BAT_Formbook_EAOH_MTB{
	meta:
		description = "Trojan:BAT/Formbook.EAOH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 0c 11 0d 17 58 1d 5a 07 11 0b 11 0d 58 07 8e 69 5d 94 61 58 13 0c 02 11 0b 11 0d ?? ?? ?? ?? ?? 13 0e 04 03 ?? ?? ?? ?? ?? 59 13 0f 11 0f 13 10 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}