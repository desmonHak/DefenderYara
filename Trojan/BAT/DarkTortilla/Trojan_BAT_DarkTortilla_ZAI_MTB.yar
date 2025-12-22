
rule Trojan_BAT_DarkTortilla_ZAI_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 14 fe 01 0c 08 2c 04 14 0a de 50 28 ?? 01 00 0a 20 39 30 00 00 61 0b 02 75 ?? 00 00 1b 14 fe 03 0d 09 2c 22 02 74 ?? 00 00 1b 13 04 11 04 8e } //5
		$a_03_1 = {02 03 17 da 9a 14 fe 01 13 07 11 07 2c 05 dd 01 01 00 00 02 03 17 da 9a 28 ?? 00 00 0a 28 ?? 02 00 06 0b 07 14 fe 01 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}