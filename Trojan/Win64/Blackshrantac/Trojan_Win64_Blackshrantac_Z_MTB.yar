
rule Trojan_Win64_Blackshrantac_Z_MTB{
	meta:
		description = "Trojan:Win64/Blackshrantac.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c8 80 e1 07 c0 e1 03 49 8b d0 48 d3 ea 66 41 23 d1 66 31 14 43 48 ff c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}