
rule Trojan_Win32_ShellcodeRunner_HP_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.HP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f 05 48 8b 4d c4 48 8d 64 cc 28 5f 48 89 45 ?? e8 00 00 00 00 } //1
		$a_03_1 = {83 e8 08 33 c9 [0-30] ba 04 00 00 00 6b c2 00 8b 4c 05 c4 33 d2 89 4d } //1
		$a_01_2 = {1c 33 c0 50 52 8d 4d e8 33 d2 52 51 8d 45 e0 33 c9 51 50 8b 45 0c 99 52 50 68 35 41 65 d2 8b 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}