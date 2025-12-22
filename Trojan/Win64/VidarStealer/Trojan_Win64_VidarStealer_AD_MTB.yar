
rule Trojan_Win64_VidarStealer_AD_MTB{
	meta:
		description = "Trojan:Win64/VidarStealer.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 89 54 24 08 48 c1 c8 13 49 33 c8 48 89 44 24 18 33 c0 48 89 1c 24 48 89 4c 24 10 8d 0c c5 ?? ?? ?? ?? 4d 8b c1 49 d3 e8 ff c0 44 32 04 32 44 88 44 14 20 48 ff c2 48 83 fa } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}