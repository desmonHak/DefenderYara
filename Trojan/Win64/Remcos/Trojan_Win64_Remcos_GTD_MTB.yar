
rule Trojan_Win64_Remcos_GTD_MTB{
	meta:
		description = "Trojan:Win64/Remcos.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 8b 7c 24 ?? 4c 8b 6c 24 ?? 41 8d 47 ?? 89 44 24 ?? 45 3b 7d ?? 73 ?? 41 8b c7 41 0f b6 44 05 ?? 33 c7 44 0f b6 e0 41 3b 76 ?? 73 ?? 8b c6 45 88 64 06 ?? ff c6 3b ee } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}