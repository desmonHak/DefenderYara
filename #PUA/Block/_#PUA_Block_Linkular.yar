
rule _#PUA_Block_Linkular{
	meta:
		description = "!#PUA:Block:Linkular,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_80_0 = {77 77 77 2e 70 70 64 69 73 74 72 6f 2e 75 73 } //www.ppdistro.us  2
		$a_80_1 = {70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //profiles.ini  1
		$a_80_2 = {6f 66 66 65 72 5f 73 63 72 65 65 6e 5f 74 79 70 65 } //offer_screen_type  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=4
 
}