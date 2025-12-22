
rule HackTool_Linux_LinuxEnum_C{
	meta:
		description = "HackTool:Linux/LinuxEnum.C,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {2f 00 6c 00 69 00 6e 00 75 00 78 00 2d 00 73 00 6d 00 61 00 72 00 74 00 2d 00 65 00 6e 00 75 00 6d 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2f 00 [0-ff] 2f 00 6c 00 73 00 65 00 2e 00 73 00 68 00 } //10
		$a_00_1 = {63 00 61 00 74 00 20 00 } //-50 cat 
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*-50) >=10
 
}