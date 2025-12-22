
rule Trojan_Win32_Razy_LM_MTB{
	meta:
		description = "Trojan:Win32/Razy.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 0d fc fe ff ff 88 84 3d fc fe ff ff 89 4d fc 88 94 0d fc fe ff ff 0f b6 8c 3d fc fe ff ff 0f b6 c2 03 c8 81 e1 ff 00 00 80 79 ?? 49 81 c9 00 ff ff ff 41 0f b6 84 0d fc fe ff ff 32 04 33 8b 4d fc 88 06 46 ff 4d 08 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}