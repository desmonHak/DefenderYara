
rule TrojanDownloader_Win64_Zusy_AUZ_MTB{
	meta:
		description = "TrojanDownloader:Win64/Zusy.AUZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b c8 48 8d 15 87 36 01 00 48 8b d8 ff 15 ?? ?? ?? ?? 48 8d 15 67 36 01 00 48 8b cb 48 89 05 25 00 02 00 ff 15 } //3
		$a_01_1 = {31 39 35 2e 36 36 2e 32 37 2e 37 37 } //2 195.66.27.77
		$a_01_2 = {38 34 2e 32 31 2e 31 38 39 2e 31 35 38 } //1 84.21.189.158
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}