
rule Trojan_Win32_DarkVNC_SX_MTB{
	meta:
		description = "Trojan:Win32/DarkVNC.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f 46 f0 66 89 35 ?? ?? ?? ?? 8b f2 0f b7 4f ?? 66 3b d1 8b c1 0f 46 f0 fe c7 } //10
		$a_01_1 = {c7 44 24 14 57 54 53 51 c7 44 24 18 75 65 72 79 c7 44 24 1c 53 65 73 73 c7 44 24 20 69 6f 6e 49 c7 44 24 24 6e 66 6f 72 c7 44 24 28 6d 61 74 69 c7 44 24 2c 6f 6e 57 00 } //5
		$a_03_2 = {0f b7 c9 0f b7 c2 c1 e1 ?? 0b c8 89 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 d2 81 f9 ?? ?? ?? ?? 0f 4c c2 a3 } //3
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5+(#a_03_2  & 1)*3) >=18
 
}