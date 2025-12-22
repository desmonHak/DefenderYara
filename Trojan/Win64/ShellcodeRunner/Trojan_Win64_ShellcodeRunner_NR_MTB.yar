
rule Trojan_Win64_ShellcodeRunner_NR_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 47 5e 22 fa 19 41 28 8d d0 72 aa 46 b7 aa 85 b8 3b 38 85 1a } //2
		$a_01_1 = {80 32 f1 45 b7 ff 4d 56 5e eb 17 bb 74 ea 1c db a3 3d 74 37 74 b0 fa 56 be bf 87 d6 c4 cd } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_Win64_ShellcodeRunner_NR_MTB_2{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 33 c4 48 89 44 24 ?? 48 8b 4a 08 45 33 c9 48 c7 44 24 ?? 00 00 00 00 ba 00 00 00 10 c7 44 24 28 80 00 00 00 c7 44 24 20 03 00 00 00 } //2
		$a_03_1 = {48 89 5c 24 ?? 33 d2 48 8b c8 48 89 7c 24 70 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}
rule Trojan_Win64_ShellcodeRunner_NR_MTB_3{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {84 00 c6 80 b0 22 00 00 00 83 3d 0d c3 1c 00 00 0f 85 fc 02 00 00 83 b8 70 22 00 00 00 74 14 48 89 44 24 30 e8 74 cf ff ff } //3
		$a_01_1 = {48 8b 4c 24 20 48 8b 51 30 48 8b 9a a0 00 00 00 48 8d 05 b1 ff 21 00 e8 ec 24 fe ff 48 85 c0 0f 95 c1 0f b6 54 24 15 09 d1 88 4c 24 17 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_Win64_ShellcodeRunner_NR_MTB_4{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 45 d0 41 b9 ?? 00 00 00 49 89 d0 ba ?? ?? 00 00 48 89 c1 e8 ?? ?? ff ff 48 8b 85 ?? ?? 00 00 48 8d 15 ?? ?? 00 00 48 89 c1 48 8b 05 } //2
		$a_03_1 = {ff d0 48 89 85 ?? ?? 00 00 4c 8b 95 ?? ?? 00 00 48 8b 85 ?? ?? 00 00 c7 44 24 ?? ?? 00 00 00 41 b9 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}