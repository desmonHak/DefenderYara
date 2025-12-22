
rule Trojan_Win32_Lazy_AHM_MTB{
	meta:
		description = "Trojan:Win32/Lazy.AHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b f4 89 75 f0 89 3e 89 7e ?? 89 7e ?? 8b 45 e0 2b 45 dc 74 } //30
		$a_01_1 = {4d 69 61 6e 56 6a 73 64 68 61 6e } //20 MianVjsdhan
		$a_01_2 = {4e 59 49 52 4e 57 52 47 } //10 NYIRNWRG
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}