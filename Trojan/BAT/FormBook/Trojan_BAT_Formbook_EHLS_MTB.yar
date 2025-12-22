
rule Trojan_BAT_Formbook_EHLS_MTB{
	meta:
		description = "Trojan:BAT/Formbook.EHLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 08 11 13 1f 3d 5a 61 13 14 00 02 11 12 11 13 ?? ?? ?? ?? ?? 13 15 04 03 ?? ?? ?? ?? ?? 59 13 16 11 16 13 17 11 17 19 fe 02 13 1d 11 1d 2c 03 19 13 17 11 17 16 fe 04 13 1e 11 1e 2c 03 16 13 17 11 08 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Formbook_EHLS_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.EHLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {5a 11 17 1a 63 61 61 13 17 16 13 41 ?? ?? ?? ?? ?? 02 11 40 11 41 ?? ?? ?? ?? ?? 13 42 03 07 ?? ?? ?? ?? ?? 59 13 43 11 43 19 31 03 19 13 43 11 43 16 2f 03 16 13 43 11 17 16 5f 13 44 } //2
		$a_03_1 = {58 19 5d 13 46 18 11 44 58 19 5d 13 47 19 ?? ?? ?? ?? ?? 13 48 11 48 16 12 42 ?? ?? ?? ?? ?? 9c 11 48 17 12 42 ?? ?? ?? ?? ?? 9c 11 48 18 12 42 ?? ?? ?? ?? ?? 9c 11 43 16 31 0b } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}