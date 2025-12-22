
rule Trojan_Win64_Redcap_AHB_MTB{
	meta:
		description = "Trojan:Win64/Redcap.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 f7 48 d1 e7 48 89 bc 24 c0 07 00 00 48 c1 ff ?? 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 4c 8b bc 24 c0 07 00 00 49 f7 ef 48 8d 04 72 48 c1 f8 ?? 48 29 f8 48 89 c2 48 c1 e0 } //30
		$a_03_1 = {48 f7 ea 49 89 d8 48 c1 fb ?? 48 c1 fa ?? 48 29 da 48 69 c2 ?? ?? ?? ?? 4c 89 c2 49 29 c0 4d 89 01 48 c1 eb ?? 4c 8d 04 1a 4c 89 c0 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}