
rule Trojan_Win64_DllHijack_KK_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b d1 4c 8d 44 17 10 0f b6 54 10 10 41 30 10 ff c1 44 3b f1 7f ea } //20
		$a_03_1 = {8b c6 48 0f af c8 48 c1 e9 ?? 6b c9 ?? 44 8b f6 44 2b f1 41 83 fe } //10
		$a_03_2 = {8b c7 48 0f af c8 48 c1 e9 ?? 6b c9 ?? 44 8b f7 44 2b f1 41 83 fe } //10
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10) >=30
 
}