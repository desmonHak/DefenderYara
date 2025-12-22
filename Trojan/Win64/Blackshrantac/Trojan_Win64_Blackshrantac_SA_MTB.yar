
rule Trojan_Win64_Blackshrantac_SA_MTB{
	meta:
		description = "Trojan:Win64/Blackshrantac.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c8 80 e1 ?? c0 e1 ?? 49 8b d0 48 d3 ea 66 41 23 d1 66 31 14 43 48 ff c0 48 83 f8 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}