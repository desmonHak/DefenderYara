
rule Trojan_Win64_Lazy_AMB_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 58 8b 4c 24 58 03 d2 33 d0 ff c0 03 ca 89 4c 24 58 3d } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}