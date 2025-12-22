
rule _#PUA_Block_Coupish{
	meta:
		description = "!#PUA:Block:Coupish,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {77 77 77 2e 63 6f 75 70 69 73 68 2e 63 6f 6d } //www.coupish.com  2
		$a_80_1 = {53 68 6f 70 70 69 6e 67 20 6f 66 66 65 72 73 } //Shopping offers  1
		$a_80_2 = {63 6f 75 70 69 73 68 5f 65 6e 2e 69 6e 69 } //coupish_en.ini  1
		$a_80_3 = {54 6f 6f 6c 62 61 72 5f 50 68 70 6e 75 6b 65 2e 65 78 65 } //Toolbar_Phpnuke.exe  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}