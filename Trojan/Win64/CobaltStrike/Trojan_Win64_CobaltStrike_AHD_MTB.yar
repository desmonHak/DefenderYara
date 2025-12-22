
rule Trojan_Win64_CobaltStrike_AHD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 ca 8b b4 24 b1 02 00 00 48 c1 e2 ?? 48 c1 e6 ?? 48 09 d6 4c 8b bc 24 b8 02 00 00 4c 8b ac 24 c0 02 00 00 48 09 c6 } //30
		$a_01_1 = {66 0f 10 84 24 20 01 00 00 66 41 0f 11 04 36 49 ff c5 4c 89 ac 24 d0 00 00 00 48 83 c6 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}