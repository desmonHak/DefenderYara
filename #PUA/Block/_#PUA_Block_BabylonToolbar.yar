
rule _#PUA_Block_BabylonToolbar{
	meta:
		description = "!#PUA:Block:BabylonToolbar,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {46 54 57 41 52 45 5c 42 61 62 79 6c 6f 6e 54 6f 6f 6c } //FTWARE\BabylonTool  1
		$a_80_1 = {77 77 77 2e 62 61 62 79 6c 6f 6e 2e 63 6f 6d 2f 72 65 64 69 72 65 63 74 73 2f 64 6f 77 6e 6c 6f 61 64 2e 63 67 69 3f 74 79 70 65 3d 37 33 31 38 } //www.babylon.com/redirects/download.cgi?type=7318  1
		$a_80_2 = {49 6e 73 74 61 6c 6c 20 42 61 62 79 6c 6f 6e 20 54 6f 6f 6c 62 61 72 20 2d 20 52 45 43 4f 4d 4d 45 4e 44 45 44 } //Install Babylon Toolbar - RECOMMENDED  1
		$a_80_3 = {43 3a 5c 50 72 6f 6a 65 63 74 73 5c 4c 69 67 68 74 49 6e 73 74 61 6c 6c 65 72 5c 74 72 75 6e 63 5c 52 65 6c 65 61 73 65 5c 4c 69 67 68 74 49 6e 73 74 61 6c 6c 65 72 2e 70 64 62 } //C:\Projects\LightInstaller\trunc\Release\LightInstaller.pdb  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}