
rule TrojanDownloader_Win64_AsyncRAT_PAGU_MTB{
	meta:
		description = "TrojanDownloader:Win64/AsyncRAT.PAGU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 08 07 08 93 0d 09 20 ff 00 00 00 5f 06 25 17 58 0a 61 1e 62 09 1e 63 06 25 17 58 0a 61 d2 60 d1 9d 18 } //2
		$a_01_1 = {43 6c 61 73 73 4c 69 62 72 61 72 79 33 } //1 ClassLibrary3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}