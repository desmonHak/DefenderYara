
rule TrojanDownloader_Win32_Phorpiex_APH_MTB{
	meta:
		description = "TrojanDownloader:Win32/Phorpiex.APH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 8d f0 fb ff ff 51 68 38 22 40 00 8d 95 f8 fd ff ff 52 ff 15 ?? ?? ?? ?? 83 c4 0c 8d 85 f8 fd ff ff 50 } //3
		$a_01_1 = {39 00 34 00 2e 00 32 00 36 00 2e 00 39 00 30 00 2e 00 32 00 33 00 35 00 2f 00 67 00 65 00 74 00 74 00 6f 00 74 00 61 00 6c 00 73 00 74 00 61 00 74 00 61 00 } //4 94.26.90.235/gettotalstata
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*4) >=7
 
}