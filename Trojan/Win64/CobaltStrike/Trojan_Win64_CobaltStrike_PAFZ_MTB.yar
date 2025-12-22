
rule Trojan_Win64_CobaltStrike_PAFZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PAFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 30 3b 84 24 0c 02 00 00 7d ?? 8b 44 24 30 99 f7 7c 24 64 48 63 c2 0f be 84 04 66 02 00 00 48 8b 8c 24 00 02 00 00 48 63 54 24 30 44 0f b6 04 11 41 31 c0 44 88 04 11 8b 44 24 30 83 c0 01 89 44 24 30 eb } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}