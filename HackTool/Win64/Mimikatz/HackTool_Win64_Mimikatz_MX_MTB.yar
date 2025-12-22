
rule HackTool_Win64_Mimikatz_MX_MTB{
	meta:
		description = "HackTool:Win64/Mimikatz.MX!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 20 00 66 00 6f 00 72 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 } //1 mimikatz for Windows
		$a_01_1 = {6b 00 69 00 77 00 69 00 20 00 66 00 6c 00 61 00 76 00 6f 00 72 00 } //1 kiwi flavor
		$a_01_2 = {42 00 75 00 69 00 6c 00 64 00 20 00 77 00 69 00 74 00 68 00 20 00 6c 00 6f 00 76 00 65 00 20 00 66 00 6f 00 72 00 20 00 50 00 4f 00 43 00 20 00 6f 00 6e 00 6c 00 79 00 } //1 Build with love for POC only
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}