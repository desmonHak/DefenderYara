
rule _#PUA_Block_DownloadStudio{
	meta:
		description = "!#PUA:Block:DownloadStudio,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {6f 66 66 65 72 73 } //offers  1
		$a_80_1 = {53 68 6f 77 50 61 67 65 } //ShowPage  1
		$a_80_2 = {6f 70 65 72 61 2e 63 6f 6d } //opera.com  1
		$a_80_3 = {6f 70 65 6e 2d 6d 61 67 6e 65 74 2d 75 72 69 } //open-magnet-uri  1
		$a_80_4 = {61 64 64 2d 74 6f 72 72 65 6e 74 } //add-torrent  1
		$a_80_5 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 62 69 74 74 6f 72 72 65 6e 74 } //application/x-bittorrent  1
		$a_80_6 = {64 73 74 75 64 69 6f 2e 65 78 65 } //dstudio.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}