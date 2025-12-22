
rule VirTool_Win64_ZomBytes_C{
	meta:
		description = "VirTool:Win64/ZomBytes.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5b 2a 5d 20 4d 65 6d 6f 72 79 20 61 6c 6c 6f 63 61 74 65 64 20 77 69 74 68 20 73 75 63 63 65 73 73 20 21 20 41 64 64 72 65 73 73 20 3a 20 25 70 0a 00 00 } //1
		$a_01_1 = {5b 21 5d 20 43 61 6e 27 74 20 61 6c 6c 6f 63 61 74 65 20 6d 65 6d 6f 72 79 20 21 20 53 54 41 54 55 53 20 3a 20 30 78 25 6c 6c } //1 [!] Can't allocate memory ! STATUS : 0x%ll
		$a_01_2 = {64 72 61 75 67 72 } //1 draugr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}