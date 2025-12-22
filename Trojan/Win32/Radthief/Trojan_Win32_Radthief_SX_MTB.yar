
rule Trojan_Win32_Radthief_SX_MTB{
	meta:
		description = "Trojan:Win32/Radthief.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 00 01 f0 ff e0 31 c0 81 fb ?? ?? ?? ?? 0f 9c c0 c1 e0 ?? 8b 80 ?? ?? ?? ?? 01 f0 ff e0 31 c0 } //3
		$a_03_1 = {0f 4c c7 8b 00 01 f0 89 d7 8b 54 24 ?? 89 54 24 ?? 89 fa ff e0 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}