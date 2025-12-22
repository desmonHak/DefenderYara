
rule _#PUA_Block_CheatEngine{
	meta:
		description = "!#PUA:Block:CheatEngine,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 68 65 61 74 65 6e 67 69 6e 65 2e 6f 72 67 } //cheatengine.org  2
		$a_80_1 = {64 31 7a 6c 75 6b 77 32 70 71 75 65 65 6e 2e 63 6c 6f 75 64 66 72 6f 6e 74 } //d1zlukw2pqueen.cloudfront  1
		$a_80_2 = {4f 66 66 65 72 } //Offer  1
		$a_80_3 = {6f 70 65 72 61 2e 65 78 65 } //opera.exe  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}