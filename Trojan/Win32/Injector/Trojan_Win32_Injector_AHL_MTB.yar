
rule Trojan_Win32_Injector_AHL_MTB{
	meta:
		description = "Trojan:Win32/Injector.AHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,5a 00 5a 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 7d a8 81 ef ?? ?? ?? ?? 2b f8 6a ?? e8 ?? ?? ?? ?? 03 f8 31 3e 83 c3 ?? 83 c6 ?? 3b 5d cc 72 } //40
		$a_03_1 = {8b 00 89 45 cc 83 45 d4 ?? 89 75 d0 8b 45 d0 83 e8 ?? 89 45 d0 } //30
		$a_01_2 = {74 65 6f 6b 68 65 68 77 75 65 } //20 teokhehwue
	condition:
		((#a_03_0  & 1)*40+(#a_03_1  & 1)*30+(#a_01_2  & 1)*20) >=90
 
}