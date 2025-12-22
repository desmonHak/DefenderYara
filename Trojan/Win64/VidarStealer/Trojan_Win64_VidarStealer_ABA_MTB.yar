
rule Trojan_Win64_VidarStealer_ABA_MTB{
	meta:
		description = "Trojan:Win64/VidarStealer.ABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c0 48 63 c8 48 8d 54 24 ?? 48 03 d1 0f b6 0a 41 88 0c 18 44 88 0a 41 0f b6 14 18 49 03 d1 0f b6 ca 0f b6 54 0c ?? 30 17 48 ff c7 49 83 ea } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win64_VidarStealer_ABA_MTB_2{
	meta:
		description = "Trojan:Win64/VidarStealer.ABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c2 0f b6 d2 44 0f b6 84 14 ?? ?? ?? ?? 44 00 c1 44 0f b6 c9 46 0f b6 94 0c ?? ?? ?? ?? 44 88 94 14 ?? ?? ?? ?? 46 88 84 0c ?? ?? ?? ?? 44 02 84 14 ?? ?? ?? ?? 45 0f b6 c0 46 0f b6 84 04 ?? ?? ?? ?? 45 30 04 04 48 ff c0 49 39 c3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}