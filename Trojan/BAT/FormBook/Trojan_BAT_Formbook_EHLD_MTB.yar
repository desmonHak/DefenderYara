
rule Trojan_BAT_Formbook_EHLD_MTB{
	meta:
		description = "Trojan:BAT/Formbook.EHLD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {5a 11 0f 1b 63 61 61 13 0f 16 13 47 ?? ?? ?? ?? ?? 00 11 0f 11 47 1f 53 5a 61 13 48 00 02 11 46 11 47 ?? ?? ?? ?? ?? 13 49 03 06 ?? ?? ?? ?? ?? 59 13 4a 11 4a 13 4b 11 4b 19 fe 02 } //2
		$a_03_1 = {58 19 5d 13 4e 18 11 4c 58 19 5d 13 4f 19 ?? ?? ?? ?? ?? 13 50 11 50 16 12 49 ?? ?? ?? ?? ?? 9c 11 50 17 12 49 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}