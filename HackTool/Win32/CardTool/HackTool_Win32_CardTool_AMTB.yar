
rule HackTool_Win32_CardTool_AMTB{
	meta:
		description = "HackTool:Win32/CardTool!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {43 61 72 64 20 54 79 70 65 20 43 20 77 69 74 68 20 62 61 63 6b 64 6f 6f 72 20 64 65 74 65 63 74 65 64 } //Card Type C with backdoor detected  1
		$a_80_1 = {46 61 69 6c 65 64 20 74 6f 20 72 65 61 64 20 63 61 72 64 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 21 } //Failed to read card information!  1
		$a_80_2 = {43 61 72 64 20 54 79 70 65 20 41 20 64 65 74 65 63 74 65 64 } //Card Type A detected  1
		$a_80_3 = {49 6e 73 65 72 74 20 63 61 72 64 20 6f 72 20 70 72 65 73 73 20 61 6e 79 20 6b 65 79 20 74 6f 20 65 78 69 74 } //Insert card or press any key to exit  1
		$a_80_4 = {46 61 69 6c 65 64 20 74 6f 20 6c 69 73 74 20 63 61 72 64 20 72 65 61 64 65 72 73 } //Failed to list card readers  1
		$a_80_5 = {43 61 72 64 20 53 65 72 69 61 6c } //Card Serial  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}