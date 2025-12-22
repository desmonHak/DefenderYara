
rule _#PUA_Block_Pisivic{
	meta:
		description = "!#PUA:Block:Pisivic,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4b 65 72 6e 65 6c 20 44 65 62 75 67 20 4c 6f 67 20 4d 65 73 73 61 67 65 73 20 28 75 73 69 6e 67 20 64 65 62 75 67 20 61 67 65 6e 74 29 } //1 Kernel Debug Log Messages (using debug agent)
		$a_01_1 = {47 65 6f 49 50 20 4c 6f 6f 6b 75 70 } //1 GeoIP Lookup
		$a_01_2 = {57 6f 57 20 28 57 69 6e 64 6f 77 73 20 6f 6e 20 57 69 6e 64 6f 77 73 29 20 36 34 2d 62 69 74 20 4f 53 20 74 6f 20 33 32 2d 62 69 74 20 61 70 70 6c 69 63 61 74 69 6f 6e 20 49 6e 6a 65 63 74 69 6f 6e 20 4d 61 6e 61 67 65 72 } //1 WoW (Windows on Windows) 64-bit OS to 32-bit application Injection Manager
		$a_01_3 = {4d 6f 7a 20 54 65 78 74 20 53 63 72 61 70 69 6e 67 20 43 6f 6c 6c 65 63 74 69 6f 6e 20 54 6f 6f 6c 20 26 20 73 63 72 69 70 74 73 } //1 Moz Text Scraping Collection Tool & scripts
		$a_01_4 = {4c 6f 74 75 73 20 4e 6f 74 65 73 20 43 6f 6c 6c 65 63 74 6f 72 } //1 Lotus Notes Collector
		$a_01_5 = {41 6c 6c 20 64 61 74 61 20 73 65 6e 74 20 74 6f 20 64 61 74 61 20 6d 61 6e 61 67 65 72 20 28 6c 69 6b 65 20 73 65 65 69 6e 67 20 64 61 74 61 20 6f 6e 20 74 68 65 20 73 65 72 76 65 72 29 } //1 All data sent to data manager (like seeing data on the server)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}