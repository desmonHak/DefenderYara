
rule _#PUA_Block_DownloadAdmin{
	meta:
		description = "!#PUA:Block:DownloadAdmin,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 62 75 69 6c 64 2f 73 68 61 72 65 64 5f 6c 69 62 72 61 72 79 2e 64 6c 6c 5d 5d } //1 .build/shared_library.dll]]
		$a_01_1 = {72 65 73 2f 6b 6e 6f 63 6b 6f 75 74 2e 6a 73 5d 5d } //1 res/knockout.js]]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=3
 
}
rule _#PUA_Block_DownloadAdmin_2{
	meta:
		description = "!#PUA:Block:DownloadAdmin,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {6c 75 61 2d 75 73 65 72 73 2e 6f 72 67 } //lua-users.org  2
		$a_80_1 = {73 74 61 72 74 49 6e 74 65 67 72 61 74 65 64 4f 66 66 65 72 } //startIntegratedOffer  1
		$a_80_2 = {55 41 43 49 6e 66 6f 2e 70 64 62 } //UACInfo.pdb  1
		$a_80_3 = {70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //profiles.ini  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}