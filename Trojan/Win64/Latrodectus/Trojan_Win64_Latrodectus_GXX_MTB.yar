
rule Trojan_Win64_Latrodectus_GXX_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.GXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 0f 38 1d e0 66 0f 6f c3 66 0f 6d c1 66 0f 6f } //5
		$a_01_1 = {66 0f 38 1d e0 66 0f 6f cb 66 0f } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}