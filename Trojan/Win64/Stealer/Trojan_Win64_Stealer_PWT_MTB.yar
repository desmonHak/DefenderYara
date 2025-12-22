
rule Trojan_Win64_Stealer_PWT_MTB{
	meta:
		description = "Trojan:Win64/Stealer.PWT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c3 0f b6 c3 8b d8 48 8d 4d ?? 48 03 c8 0f b6 11 8d 04 32 0f b6 f0 0f b6 44 35 ?? 88 01 88 54 35 ?? 0f b6 01 03 c2 0f b6 c0 0f b6 4c 05 ?? 30 0f 48 8d 7f 01 49 83 e8 01 75 c5 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}