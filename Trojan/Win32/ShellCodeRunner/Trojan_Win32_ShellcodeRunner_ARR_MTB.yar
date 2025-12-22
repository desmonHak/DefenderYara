
rule Trojan_Win32_ShellcodeRunner_ARR_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {29 c2 44 89 c0 89 d1 d3 e0 44 89 c9 09 c1 48 8b 55 f8 } //10
		$a_01_1 = {0f b6 55 ca 8b 45 f4 48 98 48 63 d2 48 c1 e2 } //8
		$a_03_2 = {48 01 d0 0f b6 00 0f b6 d0 0f b6 45 ?? 89 c1 d3 fa 89 d0 41 89 c1 48 8b 55 b8 } //2
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*8+(#a_03_2  & 1)*2) >=20
 
}