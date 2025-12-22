
rule _#PUA_Block_AskToolbar{
	meta:
		description = "!#PUA:Block:AskToolbar,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {70 69 70 6f 66 66 65 72 73 2e 61 70 6e 70 61 72 74 6e 65 72 73 2e 63 6f 6d } //pipoffers.apnpartners.com  2
		$a_80_1 = {44 69 73 70 6c 61 79 4f 66 66 65 72 } //DisplayOffer  1
		$a_80_2 = {6f 66 66 65 72 65 75 6c 61 } //offereula  1
		$a_80_3 = {41 73 6b 54 6f 6f 6c 62 61 72 } //AskToolbar  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_AskToolbar_2{
	meta:
		description = "!#PUA:Block:AskToolbar,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {61 70 6e 73 74 61 74 69 63 2e 61 73 6b 2e 63 6f 6d } //2 apnstatic.ask.com
		$a_00_1 = {6f 66 66 65 72 6c 69 73 74 } //1 offerlist
		$a_00_2 = {4f 66 66 65 72 43 61 73 74 } //1 OfferCast
		$a_00_3 = {4f 43 50 61 63 6b 65 72 2e 70 64 62 } //1 OCPacker.pdb
		$a_80_4 = {41 50 4e 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //APNInstaller.exe  1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_80_4  & 1)*1) >=6
 
}
rule _#PUA_Block_AskToolbar_3{
	meta:
		description = "!#PUA:Block:AskToolbar,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {41 73 6b 20 54 6f 6f 6c 62 61 72 2e 6d 73 69 } //Ask Toolbar.msi  2
		$a_80_1 = {77 65 62 73 65 61 72 63 68 2e 61 73 6b 2e 63 6f 6d } //websearch.ask.com  1
		$a_80_2 = {47 65 6e 65 72 69 63 41 73 6b 54 6f 6f 6c 62 61 72 2e 64 6c 6c } //GenericAskToolbar.dll  1
		$a_80_3 = {65 78 74 65 72 6e 61 6c 77 72 61 70 70 65 72 2e 70 64 62 } //externalwrapper.pdb  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule _#PUA_Block_AskToolbar_4{
	meta:
		description = "!#PUA:Block:AskToolbar,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 4a 65 6e 6b 69 6e 73 5c 77 6f 72 6b 73 70 61 63 65 5c 4f 43 33 2e 58 5c 4f 43 5c 52 65 6c 65 61 73 65 5c 4f 43 50 61 63 6b 65 72 2e 70 64 62 } //C:\Jenkins\workspace\OC3.X\OC\Release\OCPacker.pdb  1
		$a_80_1 = {4f 66 66 65 72 63 61 73 74 } //Offercast  1
		$a_80_2 = {6f 66 66 65 72 6c 69 73 74 2e 6a 73 } //offerlist.js  1
		$a_80_3 = {41 73 6b 2e 63 6f 6d } //Ask.com  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}