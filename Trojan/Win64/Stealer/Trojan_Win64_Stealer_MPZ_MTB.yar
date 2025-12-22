
rule Trojan_Win64_Stealer_MPZ_MTB{
	meta:
		description = "Trojan:Win64/Stealer.MPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 14 08 48 8b 8c 24 ?? 02 00 00 e8 34 05 00 00 8b 8c 24 ?? 01 00 00 48 03 c1 48 89 84 24 60 02 00 00 48 8b 84 24 60 02 00 00 0f b6 00 83 f0 36 48 8b 8c 24 60 02 00 00 88 01 e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}