
rule Trojan_BAT_Donut_ADN_MTB{
	meta:
		description = "Trojan:BAT/Donut.ADN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0a 02 8e 16 fe 03 0d 09 2c 0d 00 02 16 9a 12 00 28 ?? 00 00 0a 26 00 06 19 fe 02 13 04 11 04 2c 11 } //5
		$a_01_1 = {68 00 65 00 63 00 6b 00 65 00 72 00 73 00 63 00 6f 00 6f 00 6c 00 } //3 heckerscool
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*3) >=8
 
}