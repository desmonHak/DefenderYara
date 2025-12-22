
rule Trojan_Win32_Injector_KAB_MTB{
	meta:
		description = "Trojan:Win32/Injector.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 7d b8 81 ef ?? ?? ?? ?? 2b f8 31 3e 83 c3 04 83 c6 04 3b 5d e0 72 } //20
		$a_01_1 = {8b d6 03 55 c8 03 c2 8b 55 e8 03 d7 8b 4d d4 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}