
rule Trojan_BAT_DarkCloud_SL_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 9a 13 06 11 06 6f 77 01 00 0a 19 fe 04 13 07 11 07 2c 04 16 0d 2b 16 00 00 11 05 17 d6 13 05 11 05 11 04 8e 69 fe 04 13 08 11 08 2d cf } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_DarkCloud_SL_MTB_2{
	meta:
		description = "Trojan:BAT/DarkCloud.SL!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 0d 72 1d 00 00 70 2b 09 18 2d 0d 26 de 1d 07 2b f0 6f 45 00 00 0a 2b f0 0a 2b f1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}