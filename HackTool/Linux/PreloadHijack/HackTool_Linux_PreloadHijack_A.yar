
rule HackTool_Linux_PreloadHijack_A{
	meta:
		description = "HackTool:Linux/PreloadHijack.A,SIGNATURE_TYPE_ELFHSTR_EXT,1f 00 1f 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 73 6e 6f 77 5f 76 61 6c 6c 65 79 } //10 .snow_valley
		$a_01_1 = {6c 64 2e 73 6f 2e 70 72 65 6c 6f 61 64 } //1 ld.so.preload
		$a_01_2 = {65 76 69 6c 5f 72 61 62 62 69 74 } //10 evil_rabbit
		$a_01_3 = {50 45 41 43 45 5f 46 4c 41 47 } //10 PEACE_FLAG
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=31
 
}