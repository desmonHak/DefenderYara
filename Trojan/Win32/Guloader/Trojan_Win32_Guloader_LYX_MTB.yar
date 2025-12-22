
rule Trojan_Win32_Guloader_LYX_MTB{
	meta:
		description = "Trojan:Win32/Guloader.LYX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {68 79 70 6f 63 68 6f 6e 64 72 69 61 63 73 2e 65 78 65 } //1 hypochondriacs.exe
		$a_81_1 = {76 65 6a 72 73 61 74 65 6c 6c 69 74 74 65 72 73 2e 69 6d 70 } //1 vejrsatellitters.imp
		$a_81_2 = {64 61 74 61 6b 6f 6d 6d 75 6e 69 6b 61 74 69 6f 6e 73 2e 69 6e 69 } //1 datakommunikations.ini
		$a_81_3 = {6c 73 65 72 66 6f 72 6b 75 6e 64 73 6b 61 62 73 2e 69 6e 69 } //1 lserforkundskabs.ini
		$a_81_4 = {75 64 6e 61 65 76 6e 74 65 2e 6a 70 67 } //1 udnaevnte.jpg
		$a_81_5 = {73 6e 64 65 72 72 69 76 65 6e 64 65 2e 74 78 74 } //1 snderrivende.txt
		$a_81_6 = {70 72 69 6f 72 69 74 65 74 73 72 6b 6b 65 66 6c 67 65 72 6e 65 2e 6a 70 67 } //1 prioritetsrkkeflgerne.jpg
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}