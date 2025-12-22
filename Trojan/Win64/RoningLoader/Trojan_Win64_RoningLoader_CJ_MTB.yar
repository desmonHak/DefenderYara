
rule Trojan_Win64_RoningLoader_CJ_MTB{
	meta:
		description = "Trojan:Win64/RoningLoader.CJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {46 0f b6 0c 01 46 32 0c 13 41 c0 c1 04 46 88 0c 13 44 8d 49 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}