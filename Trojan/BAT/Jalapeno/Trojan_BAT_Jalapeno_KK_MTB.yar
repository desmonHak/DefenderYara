
rule Trojan_BAT_Jalapeno_KK_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f 00 7b 0e 00 00 04 20 00 00 00 40 5f 2d 03 16 2b 01 17 0a 0f 00 7b 0e 00 00 04 20 00 00 00 80 5f 2d 03 16 2b 01 17 0b 0f 00 7b 0e 00 00 04 20 00 00 00 20 5f 2d 03 16 2b 01 17 0c } //20
		$a_01_1 = {11 04 28 03 00 00 2b 13 07 11 05 28 04 00 00 2b 13 08 02 7b 01 00 00 04 11 07 28 1c 00 00 06 28 14 00 00 0a 13 09 11 09 03 28 15 00 00 0a 2c 42 11 08 12 03 7b 89 00 00 04 36 0b 72 7d 01 00 70 73 27 00 00 06 7a 02 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}