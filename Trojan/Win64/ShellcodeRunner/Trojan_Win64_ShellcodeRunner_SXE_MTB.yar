
rule Trojan_Win64_ShellcodeRunner_SXE_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.SXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {c6 45 ff 6f 80 75 00 35 80 75 01 36 80 75 02 37 34 ?? 88 45 03 c7 44 24 28 ?? ?? ?? ?? 33 c9 48 89 4c 24 20 4c 8d 4d f7 48 8d 55 ff ff 15 } //6
		$a_01_1 = {c6 44 24 30 69 80 74 24 31 37 80 74 24 32 38 80 74 24 33 39 80 74 24 34 3a 80 74 24 35 3b 80 74 24 36 3c 80 74 24 37 3d 80 74 24 38 3e 80 74 24 39 3f } //4
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*4) >=10
 
}