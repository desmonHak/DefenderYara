
rule Trojan_Win64_DonutLoader_PG_MTB{
	meta:
		description = "Trojan:Win64/DonutLoader.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b c0 83 e0 ?? 0f b6 04 08 42 30 04 06 49 ff c0 4c 3b c7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}