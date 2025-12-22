
rule Trojan_BAT_Quasar_ZIK_MTB{
	meta:
		description = "Trojan:BAT/Quasar.ZIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 11 11 09 8e 69 8d ?? 00 00 01 13 12 16 0b 2b 17 11 12 07 11 09 07 91 11 11 07 11 11 8e 69 5d 91 61 d2 9c 07 17 58 0b } //5
		$a_01_1 = {07 94 1d 5d 16 fe 01 16 fe 01 13 15 11 15 2d 0e 06 07 06 07 94 20 ff 00 00 00 61 1c 58 9e 00 07 17 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}