
rule VirTool_Win64_DmpSAM_A{
	meta:
		description = "VirTool:Win64/DmpSAM.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 72 65 61 74 65 20 61 20 53 68 61 64 6f 77 20 63 6f 70 79 } //1 create a Shadow copy
		$a_01_1 = {65 6e 63 6f 64 65 64 20 53 41 4d 20 61 6e 64 20 53 59 53 54 45 4d 20 63 6f 6e 74 65 6e 74 } //1 encoded SAM and SYSTEM content
		$a_01_2 = {53 41 4d 44 75 6d 70 } //1 SAMDump
		$a_01_3 = {53 75 63 63 65 73 73 20 73 65 6e 64 69 6e 67 20 66 69 6c 65 73 } //1 Success sending files
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}