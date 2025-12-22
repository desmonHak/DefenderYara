
rule Trojan_Win64_CobaltStrike_GVH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 04 24 48 ff c0 48 89 04 24 48 8b 44 24 38 48 39 04 24 73 40 } //2
		$a_01_1 = {33 d2 48 8b 04 24 48 f7 74 24 28 48 8b c2 48 8b 4c 24 20 0f be 04 01 48 8b 0c 24 48 8b 54 24 30 48 03 d1 48 8b ca 0f be 09 33 c8 8b c1 48 8b 0c 24 48 8b 54 24 30 48 03 d1 48 8b ca 88 01 eb aa } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}