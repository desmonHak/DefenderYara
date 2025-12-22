
rule _#PUA_Block_AirInstaller{
	meta:
		description = "!#PUA:Block:AirInstaller,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_80_0 = {41 69 72 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //AirInstaller.exe  1
		$a_80_1 = {41 69 72 49 6e 73 74 61 6c 6c 65 72 20 49 6e 63 2e } //AirInstaller Inc.  1
		$a_80_2 = {46 6c 61 73 68 20 50 6c 61 79 65 72 20 50 72 6f } //Flash Player Pro  1
		$a_80_3 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_4 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*-100+(#a_80_4  & 1)*-100) >=3
 
}
rule _#PUA_Block_AirInstaller_2{
	meta:
		description = "!#PUA:Block:AirInstaller,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {41 69 72 49 6e 73 74 61 6c 6c 65 72 44 69 73 74 72 69 62 75 74 65 64 2e 70 64 62 } //AirInstallerDistributed.pdb  2
		$a_80_1 = {44 65 63 6c 69 6e 65 4f 66 66 65 72 } //DeclineOffer  1
		$a_80_2 = {41 63 63 65 70 74 4f 66 66 65 72 } //AcceptOffer  1
		$a_80_3 = {53 6b 69 70 20 61 6c 6c 20 6f 6e 20 6f 66 66 65 72 3a } //Skip all on offer:  1
		$a_80_4 = {77 77 77 2e 69 6d 69 6e 65 6e 74 2e 63 6f 6d } //www.iminent.com  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}