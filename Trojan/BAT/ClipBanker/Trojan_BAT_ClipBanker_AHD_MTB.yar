
rule Trojan_BAT_ClipBanker_AHD_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 72 0e 0e 00 70 1b 6f 40 00 00 0a 2c 0c 02 6f 41 00 00 0a 1f 2a fe 01 2b 01 16 0d 09 13 27 11 27 2c 2f } //10
		$a_01_1 = {6f 4a 00 00 0a 13 07 12 07 28 4b 00 00 0a 58 0b 08 11 06 6f 4a 00 00 0a 13 07 12 07 28 4c 00 00 0a 28 4d 00 00 0a 0c } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}