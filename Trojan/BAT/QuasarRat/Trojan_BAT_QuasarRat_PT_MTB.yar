
rule Trojan_BAT_QuasarRat_PT_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.PT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 69 6e 61 70 6f 72 69 7a 61 6e 2e 36 38 31 33 39 30 35 2e 70 6e 67 } //5 Ginaporizan.6813905.png
		$a_01_1 = {28 18 00 00 2b 0b 06 07 06 fe 06 22 03 00 06 73 dc 01 00 0a 28 19 00 00 2b 7d a7 01 00 04 06 7b a7 01 00 04 17 da 17 d6 8d 06 00 00 01 0c 06 7b a7 01 00 04 18 da 13 05 16 13 06 2b 0b 08 11 06 14 a2 11 06 17 d6 13 06 11 06 11 05 31 ef } //2
		$a_01_2 = {00 02 03 16 03 8e 69 6f 7d 02 00 0a 00 02 6f 7e 02 00 0a 00 2a } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=8
 
}