
rule Trojan_Win64_Lazy_AO_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c3 20 cb 89 c2 30 ca 08 da 80 f2 01 44 30 c8 f6 d0 44 20 c8 44 30 c1 f6 d1 44 20 c1 89 c3 80 f3 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}