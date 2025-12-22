
rule _#PUA_Block_MediaDrug{
	meta:
		description = "!#PUA:Block:MediaDrug,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_80_0 = {64 6a 2d 75 70 64 61 74 65 73 2e 63 6f 6d } //dj-updates.com  2
		$a_80_1 = {64 6c 2d 63 6f 6e 66 69 67 2d 76 6b 64 6a 2e 74 78 74 } //dl-config-vkdj.txt  1
		$a_80_2 = {64 65 6b 73 62 76 6f 75 62 7a 73 65 74 75 70 2e 69 6e 69 } //deksbvoubzsetup.ini  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=4
 
}