
rule VirTool_Win32_Autesz_A_MTB{
	meta:
		description = "VirTool:Win32/Autesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {33 f6 56 51 [0-12] 50 ?? ?? ?? ?? ?? 8b cf ?? ?? ?? ?? ?? 83 c4 10 85 c0 ?? ?? 85 f6 } //1
		$a_03_1 = {8b 44 24 04 56 8b 74 24 10 85 c0 ?? ?? 56 ff 74 24 10 50 ff 35 f4 8e 4e 00 ?? ?? ?? ?? ?? ?? 5e c2 0c 00 8b 4e 10 81 f9 [0-10] 83 66 } //1
		$a_00_2 = {45 6e 75 6d 65 72 61 74 65 44 43 73 } //1 EnumerateDCs
		$a_00_3 = {4b 65 79 6c 6f 67 67 65 72 } //1 Keylogger
		$a_00_4 = {53 65 6e 64 4c 6f 67 67 65 72 44 61 74 61 } //1 SendLoggerData
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}