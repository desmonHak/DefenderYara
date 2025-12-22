
rule _#PUA_Block_Softonic{
	meta:
		description = "!#PUA:Block:Softonic,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_80_0 = {66 72 6f 73 74 77 69 72 65 2d 77 69 6e 2e 73 64 2e 65 6e 2e 73 6f 66 74 6f 6e 69 63 2e 63 6f 6d } //frostwire-win.sd.en.softonic.com  2
		$a_80_1 = {75 6e 69 76 65 72 73 61 6c 64 6f 77 6e 6c 6f 61 64 65 72 2d 70 72 65 66 65 74 63 68 } //universaldownloader-prefetch  1
		$a_80_2 = {53 6f 66 74 6f 6e 69 63 44 6f 77 6e 6c 6f 61 64 65 72 2e 65 78 65 } //SoftonicDownloader.exe  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=4
 
}