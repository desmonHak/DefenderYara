
rule VirTool_Win64_Anebesz_A{
	meta:
		description = "VirTool:Win64/Anebesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 68 48 39 44 24 50 ?? ?? ?? ?? ?? ?? 48 63 44 24 34 48 8b 4c 24 38 0f b7 04 41 3d 00 d8 00 00 ?? ?? ?? ?? ?? ?? 48 63 44 24 34 48 8b 4c 24 38 0f b7 04 41 3d } //1
		$a_03_1 = {8b 44 24 44 05 ff 00 00 00 39 44 24 4c ?? ?? 8b 44 24 44 8b 4c 24 4c 2b c8 8b c1 48 8b 4c 24 50 48 8b 54 24 70 48 03 d1 48 8b ca 88 01 48 8b 44 24 50 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}