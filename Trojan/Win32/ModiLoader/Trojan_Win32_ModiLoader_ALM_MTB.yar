
rule Trojan_Win32_ModiLoader_ALM_MTB{
	meta:
		description = "Trojan:Win32/ModiLoader.ALM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d8 68 6c 2e 44 00 53 e8 ?? ?? ?? ?? a3 44 f5 56 00 83 3d 7c f5 46 00 00 0f 85 ee 00 00 00 68 7c 2e 44 00 e8 ?? ?? ?? ?? a3 7c f5 46 00 83 3d 7c f5 46 00 00 0f 84 d2 00 00 00 68 88 2e 44 00 a1 7c f5 46 00 50 e8 ?? ?? ?? ?? a3 48 f5 56 00 68 98 2e 44 00 } //2
		$a_03_1 = {68 dc 2e 44 00 a1 7c f5 46 00 50 e8 ?? ?? ?? ?? a3 58 f5 56 00 68 f0 2e 44 00 a1 7c f5 46 00 50 e8 ?? ?? ?? ?? a3 5c f5 56 00 68 08 2f 44 00 a1 7c f5 46 00 50 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}