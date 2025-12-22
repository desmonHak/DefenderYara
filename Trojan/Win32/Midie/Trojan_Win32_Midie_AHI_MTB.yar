
rule Trojan_Win32_Midie_AHI_MTB{
	meta:
		description = "Trojan:Win32/Midie.AHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 8c 89 45 d4 8b 45 d8 89 45 c4 c7 45 bc ?? ?? ?? ?? 8b 45 d4 6b c0 } //30
		$a_03_1 = {89 85 78 ff ff ff 8b 45 d4 03 45 a0 66 0f b6 08 8b 45 ?? 66 2b 08 0f } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}