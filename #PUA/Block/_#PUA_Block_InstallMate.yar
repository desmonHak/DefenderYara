
rule _#PUA_Block_InstallMate{
	meta:
		description = "!#PUA:Block:InstallMate,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {77 77 77 2e 69 6e 73 74 61 6c 6c 6d 61 74 65 2e 63 6f 6d } //www.installmate.com  2
		$a_80_1 = {54 69 6e 44 65 6c 2e 70 64 62 } //TinDel.pdb  1
		$a_80_2 = {73 63 68 65 64 75 6c 65 72 2e 69 6e 69 } //scheduler.ini  1
		$a_80_3 = {53 6b 69 70 4f 66 66 65 72 } //SkipOffer  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}