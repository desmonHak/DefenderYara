
rule Trojan_Win64_DonuLoader_EI_MTB{
	meta:
		description = "Trojan:Win64/DonuLoader.EI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 f7 f1 48 8b c2 48 6b c0 ?? 48 8d 8c 24 ?? ?? ?? ?? 48 03 c8 48 8b c1 0f b6 00 8b 4c 24 ?? 33 c8 8b c1 88 44 24 ?? 48 8d 54 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}