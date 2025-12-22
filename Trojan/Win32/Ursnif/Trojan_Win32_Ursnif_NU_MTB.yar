
rule Trojan_Win32_Ursnif_NU_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d6 2b d1 2b c5 83 c2 ?? 3b d7 8b e8 89 2d ?? ?? ?? 00 75 0c 8b c7 69 c0 ?? ?? 00 00 2b c6 8b f0 } //2
		$a_03_1 = {33 c9 85 f6 0f 94 c1 85 c9 74 2b b8 ?? ?? ?? ?? f7 e6 c1 ea 05 3b fa 74 07 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}