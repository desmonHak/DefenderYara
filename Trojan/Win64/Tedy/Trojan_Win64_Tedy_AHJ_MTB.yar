
rule Trojan_Win64_Tedy_AHJ_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 2e 0f 1f 84 ?? ?? ?? ?? ?? b8 ?? ?? ?? ?? f6 22 88 02 48 8d 36 48 87 f6 48 89 f6 48 8d 36 } //30
		$a_03_1 = {4c 89 c8 0f 1f 84 ?? ?? ?? ?? ?? 80 30 ?? 41 54 4d 89 e4 41 5c 48 83 c0 ?? 48 39 c1 75 ?? 4c 89 ca } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}