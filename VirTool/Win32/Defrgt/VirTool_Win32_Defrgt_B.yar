
rule VirTool_Win32_Defrgt_B{
	meta:
		description = "VirTool:Win32/Defrgt.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 00 ff 75 e8 0f 47 45 08 50 57 56 ff } //1
		$a_01_1 = {83 c4 18 68 00 80 00 00 6a 00 57 56 ff } //1
		$a_01_2 = {49 00 6e 00 6a 00 65 00 63 00 74 00 69 00 6f 00 6e 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}