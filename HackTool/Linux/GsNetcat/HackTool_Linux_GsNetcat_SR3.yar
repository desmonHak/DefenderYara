
rule HackTool_Linux_GsNetcat_SR3{
	meta:
		description = "HackTool:Linux/GsNetcat.SR3,SIGNATURE_TYPE_ELFHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_80_0 = {72 65 76 65 72 73 65 20 73 68 65 6c 6c } //reverse shell  2
		$a_80_1 = {62 61 63 6b 64 6f 6f 72 20 } //backdoor   2
		$a_80_2 = {62 61 63 6b 73 68 65 6c 6c } //backshell  2
		$a_80_3 = {2f 62 69 6e 2f 73 68 } ///bin/sh  2
		$a_80_4 = {2f 62 69 6e 2f 62 61 73 68 } ///bin/bash  2
		$a_80_5 = {67 73 2d 6e 65 74 63 61 74 20 2d } //gs-netcat -  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2) >=10
 
}