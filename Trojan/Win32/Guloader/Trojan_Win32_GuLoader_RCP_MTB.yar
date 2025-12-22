
rule Trojan_Win32_GuLoader_RCP_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {23 5c 43 6c 69 65 6e 74 6c 65 73 73 31 32 5c 61 66 67 6e 61 76 65 64 65 73 } //1 #\Clientless12\afgnavedes
		$a_81_1 = {35 5c 53 75 6e 62 6c 6f 63 6b 34 31 5c 73 63 61 62 69 73 68 2e 69 6e 69 } //1 5\Sunblock41\scabish.ini
		$a_81_2 = {68 76 69 64 74 65 6b 61 6c 6b 65 6e 73 20 69 6e 6b 77 6f 6f 64 20 66 69 64 64 6c 65 77 6f 6f 64 } //1 hvidtekalkens inkwood fiddlewood
		$a_81_3 = {73 74 72 69 67 61 65 20 63 68 72 6f 6d 61 74 6f 73 70 68 65 72 69 63 } //1 strigae chromatospheric
		$a_81_4 = {6d 75 73 6b 61 74 65 6e 73 } //1 muskatens
		$a_81_5 = {61 64 76 61 72 73 6c 65 72 6e 65 2e 65 78 65 } //1 advarslerne.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}