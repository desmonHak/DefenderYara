
rule VirTool_Win64_LibSys_A{
	meta:
		description = "VirTool:Win64/LibSys.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 31 db 4d 31 d2 49 89 cb 49 89 d2 c3 } //1
		$a_01_1 = {41 52 48 31 c0 49 89 ca 44 89 d8 c3 } //1
		$a_01_2 = {0f b7 45 ee 48 8b 55 18 48 01 d0 0f b6 00 3c e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}