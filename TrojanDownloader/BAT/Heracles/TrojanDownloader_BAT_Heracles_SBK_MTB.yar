
rule TrojanDownloader_BAT_Heracles_SBK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.SBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 01 11 05 16 11 06 6f 0f 00 00 0a 38 0a 00 00 00 38 05 00 00 00 38 e5 ff ff ff 11 04 11 05 16 11 05 8e 69 6f 10 00 00 0a 25 13 06 16 3d ce ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule TrojanDownloader_BAT_Heracles_SBK_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Heracles.SBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 09 00 00 06 25 11 00 28 01 00 00 0a 7d 02 00 00 04 6f 07 00 00 06 38 00 00 00 00 2a 7e 06 00 00 04 28 0f 00 00 06 28 0c 00 00 06 13 00 38 cd ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}