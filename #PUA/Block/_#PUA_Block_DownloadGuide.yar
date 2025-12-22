
rule _#PUA_Block_DownloadGuide{
	meta:
		description = "!#PUA:Block:DownloadGuide,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {30 2b 06 03 55 04 0a 0c ?? 53 65 63 75 72 65 20 31 30 30 30 20 55 47 20 28 68 61 66 74 75 6e 67 73 62 65 73 63 68 72 c3 a4 6e 6b 74 29 31 2d 30 } //1
		$a_01_1 = {9a 00 3d 00 01 00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 20 00 20 00 20 00 20 00 } //1
		$a_01_2 = {65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 53 00 65 00 74 00 75 00 70 00 20 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#PUA_Block_DownloadGuide_2{
	meta:
		description = "!#PUA:Block:DownloadGuide,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {73 6f 66 74 77 61 72 65 2d 63 61 6d 70 61 69 67 6e 2d 72 65 73 6f 75 72 63 65 73 2d 63 70 70 2e 73 33 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 2f 74 65 73 74 2f 44 6f 77 6e 6c 6f 61 64 47 75 69 64 65 32 4d 54 61 67 67 65 64 2e 65 78 65 } //software-campaign-resources-cpp.s3.amazonaws.com/test/DownloadGuide2MTagged.exe  1
		$a_80_1 = {64 6c 67 2d 6d 65 73 73 61 67 65 73 2e 62 75 7a 7a 72 69 6e 2e 64 65 } //dlg-messages.buzzrin.de  1
		$a_80_2 = {70 61 67 65 20 66 6f 72 20 68 69 64 64 65 6e 20 6f 66 66 65 72 73 } //page for hidden offers  1
		$a_80_3 = {64 6f 77 6e 6c 6f 61 64 41 6e 64 49 6e 73 74 61 6c 6c 4f 66 66 65 72 73 } //downloadAndInstallOffers  1
		$a_80_4 = {61 63 63 65 70 74 20 6f 72 20 64 72 6f 70 20 6f 66 66 65 72 } //accept or drop offer  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}