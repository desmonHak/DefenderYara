
rule Trojan_Win64_XWorm_BAA_MTB{
	meta:
		description = "Trojan:Win64/XWorm.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 0f 11 7c 24 60 48 89 c2 48 c1 f8 3f 48 89 c1 48 b8 65 21 0b 59 c8 42 16 b2 48 89 d3 48 f7 ea 48 01 da 48 c1 fa 04 48 29 ca 48 6b d2 17 48 89 d8 48 29 d3 48 83 fb 02 0f 8f 5e 01 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}