
rule HackTool_Win64_EdrRedir_B{
	meta:
		description = "HackTool:Win64/EdrRedir.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {62 00 69 00 6e 00 64 00 66 00 6c 00 74 00 61 00 70 00 69 00 2e 00 64 00 6c 00 6c 00 } //1 bindfltapi.dll
		$a_00_1 = {4f 00 53 00 20 00 4e 00 4f 00 54 00 20 00 53 00 55 00 50 00 50 00 4f 00 52 00 54 00 } //1 OS NOT SUPPORT
		$a_00_2 = {42 00 69 00 6e 00 64 00 20 00 4c 00 69 00 6e 00 6b 00 } //1 Bind Link
		$a_00_3 = {42 66 53 65 74 75 70 46 69 6c 74 65 72 } //1 BfSetupFilter
		$a_00_4 = {42 66 52 65 6d 6f 76 65 4d 61 70 70 69 6e 67 } //1 BfRemoveMapping
		$a_03_5 = {d3 00 43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 57 [0-20] 46 69 6e 64 46 69 72 73 74 46 69 6c 65 57 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}