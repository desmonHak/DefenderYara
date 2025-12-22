
rule _#PUA_Block_PremiumInstaller{
	meta:
		description = "!#PUA:Block:PremiumInstaller,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {69 6e 73 74 61 6c 6c 2e 6f 69 6e 73 74 61 6c 6c 65 72 32 2e 63 6f 6d } //install.oinstaller2.com  2
		$a_80_1 = {50 6c 61 79 65 72 2d 43 68 72 6f 6d 65 2e 65 78 65 } //Player-Chrome.exe  1
		$a_80_2 = {6f 66 66 65 72 } //offer  1
		$a_80_3 = {4c 6f 61 64 65 72 5f 52 65 73 69 7a 65 64 2e 70 64 62 } //Loader_Resized.pdb  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}