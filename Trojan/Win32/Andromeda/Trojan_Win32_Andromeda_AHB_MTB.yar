
rule Trojan_Win32_Andromeda_AHB_MTB{
	meta:
		description = "Trojan:Win32/Andromeda.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b cf 2b f7 8a 04 0e 8d 49 01 88 41 ff 42 8b 44 24 0c 3b d0 72 } //20
		$a_03_1 = {8b c1 c1 e8 ?? 30 04 3a 42 3b 54 24 0c 7c ?? 89 0d ?? ?? ?? ?? 8b cf } //30
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}