
rule Trojan_BAT_Quasar_AJKB_MTB{
	meta:
		description = "Trojan:BAT/Quasar.AJKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 08 02 08 91 06 08 03 6f ?? 00 00 0a 5d 91 61 d2 9c 08 17 58 0c 08 02 8e 69 fe 04 13 04 11 04 2d de } //5
		$a_01_1 = {07 08 02 08 91 06 08 06 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 02 8e 69 fe 04 13 04 11 04 2d e1 } //5
		$a_01_2 = {11 12 07 11 09 07 91 11 11 07 11 11 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 11 09 8e 69 fe 04 13 16 11 16 2d dc } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=5
 
}