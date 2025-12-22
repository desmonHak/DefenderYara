
rule Trojan_Win64_Lazy_ADA_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 d3 20 c1 08 d9 89 d3 20 c3 30 c2 08 da 89 d0 30 c8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}