
rule Trojan_BAT_Heracles_AHB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AHB!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 3a 04 00 00 16 02 28 01 00 00 06 0a 06 7e 05 00 00 0a 28 06 00 00 0a 2c 02 16 2a 06 7e 05 00 00 0a 03 8e 69 20 00 30 00 00 1f 40 28 03 00 00 06 } //2
		$a_01_1 = {28 07 00 00 06 13 04 11 04 7e 05 00 00 0a 28 06 00 00 0a 2c 09 06 28 02 00 00 06 26 16 2a 06 28 02 00 00 06 26 17 2a } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}