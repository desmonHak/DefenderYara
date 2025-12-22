
rule TrojanDownloader_Win64_Oader_ARAX_MTB{
	meta:
		description = "TrojanDownloader:Win64/Oader.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 24 8b d0 0f af d0 ff c0 03 d1 89 54 24 24 3d 50 c3 00 00 7c e8 } //2
		$a_01_1 = {52 75 6e 74 69 6d 65 42 72 6f 6b 65 72 2e 65 78 65 } //1 RuntimeBroker.exe
		$a_01_2 = {64 6c 6c 68 6f 73 74 2e 65 78 65 } //1 dllhost.exe
		$a_01_3 = {74 61 73 6b 68 6f 73 74 77 2e 65 78 65 } //1 taskhostw.exe
		$a_01_4 = {62 61 63 6b 67 72 6f 75 6e 64 54 61 73 6b 48 6f 73 74 2e 65 78 65 } //1 backgroundTaskHost.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}