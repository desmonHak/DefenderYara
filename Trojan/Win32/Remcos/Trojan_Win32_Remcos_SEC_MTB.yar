
rule Trojan_Win32_Remcos_SEC_MTB{
	meta:
		description = "Trojan:Win32/Remcos.SEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c2 8b 55 f0 89 45 d4 8b 45 e0 a2 ?? ?? ?? ?? 33 c1 0f af d6 89 45 e0 8a 45 e4 c7 45 f0 ?? ?? ?? ?? 32 c2 89 55 dc a2 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 45 d4 a2 ?? ?? ?? ?? 8b 45 e0 0b 45 e8 2b 45 e0 89 45 d8 ff 15 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}