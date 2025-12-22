
rule _#LoD_VirTool_Win32_Obfuscator{
	meta:
		description = "!#LoD:VirTool:Win32/Obfuscator.ACW,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 89 d8 89 e7 bf b6 74 75 5d e8 ?? 00 00 00 5b 50 89 d8 89 e7 bf 22 07 e4 71 e8 ?? 00 00 00 89 c2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule _#LoD_VirTool_Win32_Obfuscator_2{
	meta:
		description = "!#LoD:VirTool:Win32/Obfuscator.ACW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 0b 00 00 "
		
	strings :
		$a_0b_0 = {bf b6 74 75 5d e8 ?? ?? 00 00 5b 50 89 d8 89 e7 bf 22 07 e4 71 (eb|e8 ?? ?? 00 00 )} //2
		$a_0b_1 = {89 85 f4 fd ff ff 58 68 b6 74 75 5d 50 e8 ?? ?? 00 00 fc 89 85 ec fd ff ff } //2
		$a_0b_2 = {bf b6 74 75 5d e8 ?? ?? 00 00 [0-08] 89 d8 89 e7 bf 22 07 e4 71 e8 ?? ?? 00 00 } //2
		$a_0b_3 = {29 ff 81 ef 4a 8b 8a a2 ?? e8 ?? ?? 00 00 [0-10] 81 c7 22 07 e4 71 } //2
		$a_03_4 = {89 85 f4 fd ff ff 68 b6 74 75 5d 57 e8 ?? ?? 00 00 } //2
		$a_0b_5 = {bf b6 74 75 5d e8 ?? ?? 00 00 5b [0-01] 50 89 d8 89 ef bf 22 07 e4 71 e8 ?? ?? 00 00 } //2
		$a_03_6 = {89 85 f4 fd ff ff 68 b6 74 75 5d 57 ?? e8 ?? ?? 00 00 89 85 ec fd ff ff } //2
		$a_0b_7 = {53 89 d8 89 e7 bf b6 74 75 5d e8 ?? ?? 00 00 } //1
		$a_0b_8 = {50 89 d8 89 ef bf 22 07 e4 71 e8 ?? ?? 00 00 } //1
		$a_0b_9 = {bf b6 74 75 5d e8 ?? ?? 00 00 5b 50 89 d8 89 e7 } //1
		$a_0b_10 = {bf 22 07 e4 71 e8 ?? ?? 00 00 } //1
	condition:
		((#a_0b_0  & 1)*2+(#a_0b_1  & 1)*2+(#a_0b_2  & 1)*2+(#a_0b_3  & 1)*2+(#a_03_4  & 1)*2+(#a_0b_5  & 1)*2+(#a_03_6  & 1)*2+(#a_0b_7  & 1)*1+(#a_0b_8  & 1)*1+(#a_0b_9  & 1)*1+(#a_0b_10  & 1)*1) >=2
 
}