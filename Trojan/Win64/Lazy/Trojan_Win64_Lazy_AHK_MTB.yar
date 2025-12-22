
rule Trojan_Win64_Lazy_AHK_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 0f 6f 4d 00 f3 0f 6f 05 ?? ?? ?? ?? 0f 57 c8 66 0f 7f 4d 00 48 8d 45 00 49 8b cd } //20
		$a_03_1 = {48 8b 45 00 48 89 85 f0 00 00 00 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 45 00 48 8b 45 00 48 89 85 ?? 00 00 00 49 8b c7 } //30
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}
rule Trojan_Win64_Lazy_AHK_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.AHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 0f b7 fb 66 44 0f a3 ff 66 0f ab d7 42 8b bc 19 ?? ?? ?? ?? 66 45 3b e8 41 80 f8 ?? 4a 8d 3c 1f 49 3b fb 0f } //30
		$a_03_1 = {0f be ca 48 1b d0 66 41 23 d7 f9 41 33 c9 e9 00 00 00 00 44 69 c9 ?? ?? ?? ?? 66 0f a4 d2 ?? 0f 94 c6 41 0f b6 10 4d 8d 40 ?? 41 f6 c6 ?? 84 d2 0f } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}