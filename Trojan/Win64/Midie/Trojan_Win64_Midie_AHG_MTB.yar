
rule Trojan_Win64_Midie_AHG_MTB{
	meta:
		description = "Trojan:Win64/Midie.AHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 24 27 c1 e1 ?? 48 63 c9 48 09 c1 0f b6 44 24 24 c1 e0 ?? 48 09 c8 0f b7 4c 24 22 48 09 c1 } //30
		$a_03_1 = {48 89 c1 ba ?? ?? ?? ?? 4c 0f af ea 49 c1 ed ?? 48 c7 40 78 00 00 00 00 4c 8d 80 88 00 00 00 4c 89 80 80 00 00 00 4c 8d 88 10 01 00 00 4d 8d 45 ff } //10
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*10) >=40
 
}