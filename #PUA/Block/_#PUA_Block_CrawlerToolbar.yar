
rule _#PUA_Block_CrawlerToolbar{
	meta:
		description = "!#PUA:Block:CrawlerToolbar,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_80_0 = {77 77 77 2e 32 34 78 37 68 65 6c 70 2e 6f 72 67 } //www.24x7help.org  2
		$a_80_1 = {77 77 77 2e 77 65 62 73 65 61 72 63 68 2e 63 6f 6d } //www.websearch.com  1
		$a_80_2 = {64 6e 6c 2e 61 70 70 67 72 61 66 66 69 74 69 2e 63 6f 6d } //dnl.appgraffiti.com  1
		$a_80_3 = {57 65 62 53 65 61 72 63 68 2e 65 78 65 } //WebSearch.exe  1
		$a_80_4 = {54 6f 6f 6c 62 61 72 } //Toolbar  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=6
 
}
rule _#PUA_Block_CrawlerToolbar_2{
	meta:
		description = "!#PUA:Block:CrawlerToolbar,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_80_0 = {64 6e 6c 2e 61 70 70 67 72 61 66 66 69 74 69 2e 63 6f 6d } //dnl.appgraffiti.com  2
		$a_80_1 = {41 70 70 47 72 61 66 66 69 74 69 53 65 74 75 70 2e 65 78 65 } //AppGraffitiSetup.exe  1
		$a_80_2 = {64 6f 77 6e 6c 6f 61 64 2e 72 65 62 61 74 65 62 6c 61 73 74 2e 63 6f 6d } //download.rebateblast.com  1
		$a_80_3 = {52 65 62 61 74 65 49 6e 66 6f 72 6d 65 72 53 65 74 75 70 2e 65 78 65 } //RebateInformerSetup.exe  1
		$a_80_4 = {54 52 49 41 4c 20 4f 46 46 45 52 53 } //TRIAL OFFERS  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=6
 
}