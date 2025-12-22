
rule TrojanDownloader_BAT_Barys_MK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Barys.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {26 06 28 0a 00 00 06 0b 07 16 fe 02 16 fe 01 0d 09 2d 36 00 20 ff 0f 1f 00 16 06 28 07 00 00 06 } //15
		$a_01_1 = {02 8e 69 17 fe 01 0d 09 2d 02 2b 75 02 16 9a 28 04 00 00 0a 0a 2b 65 } //10
		$a_01_2 = {16 fe 01 0d 09 2d 15 00 08 20 00 01 00 00 28 08 00 00 06 26 08 28 06 00 00 06 26 } //5
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=30
 
}