
rule Trojan_Win32_Zusy_LMM_MTB{
	meta:
		description = "Trojan:Win32/Zusy.LMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 84 8b 85 20 ff ff ff 8d 4c 10 dc 0f b6 95 4e ff ff ff 83 c2 3f 23 ca 88 4d e7 8b 85 20 ff ff ff 83 c8 13 8b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b c1 66 89 45 90 90 8b 55 ec 83 c2 63 2b 95 40 ff ff ff 89 55 88 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}