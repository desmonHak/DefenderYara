
rule Trojan_Win64_Lazy_AT_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 89 c2 20 c2 20 d9 08 d1 44 30 c0 89 da 44 20 c2 44 30 c3 08 d3 89 c2 30 da 08 c3 80 f3 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}