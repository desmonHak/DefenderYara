
rule Trojan_Win64_XLoader_AKQ_MTB{
	meta:
		description = "Trojan:Win64/XLoader.AKQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 8b d2 47 0f b6 54 17 10 45 30 10 ff c2 3b d1 7c e0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}