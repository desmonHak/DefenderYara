
rule TrojanDownloader_BAT_Injuke_ARR_MTB{
	meta:
		description = "TrojanDownloader:BAT/Injuke.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 03 00 00 "
		
	strings :
		$a_03_0 = {04 11 05 07 11 05 91 28 ?? ?? ?? ?? 11 05 17 58 13 05 11 05 07 8e 69 32 e2 } //25
		$a_03_1 = {07 2c 06 07 6f ?? ?? ?? 0a dc 06 28 ?? ?? ?? 06 2c 0c 72 85 04 00 70 28 ?? ?? ?? 0a 2b 0a 72 } //15
		$a_03_2 = {08 7e 07 00 00 04 07 6f ?? ?? ?? ?? de 0a 08 2c 06 } //10
	condition:
		((#a_03_0  & 1)*25+(#a_03_1  & 1)*15+(#a_03_2  & 1)*10) >=50
 
}