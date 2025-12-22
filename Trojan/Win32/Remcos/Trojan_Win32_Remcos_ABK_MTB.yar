
rule Trojan_Win32_Remcos_ABK_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 15 ?? ?? ?? ?? 8b 8d ec ee ff ff 03 8d 68 fa ff ff 0f b6 11 33 d0 8b 85 ec ee ff ff 03 85 68 fa ff ff 88 10 e9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}