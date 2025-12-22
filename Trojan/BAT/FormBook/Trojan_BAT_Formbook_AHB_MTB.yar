
rule Trojan_BAT_Formbook_AHB_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {26 11 06 20 d2 00 00 00 94 20 b6 5f 00 00 59 13 05 2b b1 16 0a 1c 13 05 2b aa 03 04 61 1f 24 59 06 61 } //20
		$a_01_1 = {06 17 58 0a 20 a4 01 00 00 0d 20 d6 02 00 00 0c 20 82 08 00 00 08 09 19 5a 59 30 09 1f 0a 13 05 } //30
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*30) >=50
 
}