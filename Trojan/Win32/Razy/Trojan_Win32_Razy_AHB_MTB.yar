
rule Trojan_Win32_Razy_AHB_MTB{
	meta:
		description = "Trojan:Win32/Razy.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 30 35 ?? ?? ?? ?? 8b 4c 24 30 8b 54 24 34 0f af ca 8b 74 24 30 89 44 24 14 89 f0 f7 e6 01 ca } //30
		$a_03_1 = {d3 ef 66 35 ?? ?? 66 8b 1e 89 7c 24 78 8b 74 24 68 66 89 c1 66 d3 eb 0f b7 fb 66 81 f2 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}