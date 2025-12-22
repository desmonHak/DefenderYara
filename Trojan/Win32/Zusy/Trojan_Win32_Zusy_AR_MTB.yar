
rule Trojan_Win32_Zusy_AR_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {12 6f 33 24 75 08 c7 44 24 ?? 9f 86 01 00 21 d7 24 83 7c } //30
		$a_03_1 = {00 38 21 7f 00 30 2d ?? ?? ?? ?? c5 6a 1a 21 81 ?? ?? ?? ?? 0c ?? 44 24 ?? a1 } //20
		$a_01_2 = {30 32 42 00 00 00 00 00 2e 3f 41 56 5f } //10
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}