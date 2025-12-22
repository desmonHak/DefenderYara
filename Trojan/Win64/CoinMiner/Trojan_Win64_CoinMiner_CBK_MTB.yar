
rule Trojan_Win64_CoinMiner_CBK_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.CBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 04 24 0f b6 0d ?? ?? ?? ?? 0f b7 44 44 ?? 33 c1 48 63 0c 24 66 89 44 4c ?? 48 63 04 24 0f b7 44 44 ?? 0f b7 4c 24 ?? 3b c1 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}