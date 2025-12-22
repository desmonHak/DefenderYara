
rule TrojanDownloader_Win64_XWorm_SX_MTB{
	meta:
		description = "TrojanDownloader:Win64/XWorm.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 0f 6e c8 f3 0f e6 c9 f2 0f 58 c0 f2 0f 5c c8 f2 0f 59 ca f2 0f 11 4c 24 30 45 8d 14 5e 44 03 d3 } //3
		$a_03_1 = {4c 8d 45 cf 44 89 74 24 28 48 8d 15 ?? ?? ?? ?? 4c 0f 47 45 cf 45 33 c9 33 c9 48 89 74 24 20 ff 15 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}