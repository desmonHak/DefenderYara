
rule Trojan_Win32_BitterSeashell_B_dha{
	meta:
		description = "Trojan:Win32/BitterSeashell.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_02_0 = {8a 44 15 b0 02 45 e8 28 04 39 8b ?? ?? 41 89 ?? ?? 81 f9 } //1
		$a_02_1 = {6a 04 68 00 30 00 00 68 ?? ?? ?? ?? 6a 00 ff d0 } //5
		$a_01_2 = {30 0a 00 00 31 0a 00 00 32 0a 00 00 33 0a 00 00 34 0a 00 00 35 0a 00 00 36 0a 00 00 37 0a 00 00 38 0a 00 00 38 38 38 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*5+(#a_01_2  & 1)*1) >=6
 
}