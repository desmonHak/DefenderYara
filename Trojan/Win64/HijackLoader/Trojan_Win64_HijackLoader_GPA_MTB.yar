
rule Trojan_Win64_HijackLoader_GPA_MTB{
	meta:
		description = "Trojan:Win64/HijackLoader.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 3e 48 8b 84 24 ?? ?? 00 00 8a 08 48 8b 84 24 ?? ?? 00 00 88 08 48 8b 84 24 ?? ?? 00 00 48 83 c0 01 48 89 84 24 ?? ?? 00 00 48 8b 84 24 ?? ?? 00 00 48 83 c0 01 48 89 84 24 ?? ?? 00 00 eb a5 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}