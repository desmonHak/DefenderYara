
rule Trojan_Win64_CobaltStrike_GVJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GVJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f 93 c0 0f b6 c0 48 c1 e0 04 48 8d 0d ?? ?? ?? ?? 48 8b 04 08 48 b9 [0-08] 48 01 c8 ff e0 48 8b 44 24 48 48 8b 4c 24 60 48 89 ca 48 83 c2 01 48 89 54 24 60 8a 09 88 08 48 8b 44 24 48 48 83 c0 01 48 89 44 24 48 48 8b 44 24 40 48 83 c0 01 48 89 44 24 40 } //2
		$a_01_1 = {66 5f 75 5f 63 5f 6b 2e 2e 2e 2e 2e 2e } //1 f_u_c_k......
	condition:
		((#a_02_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}