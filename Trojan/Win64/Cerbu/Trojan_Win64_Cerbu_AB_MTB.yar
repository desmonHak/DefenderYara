
rule Trojan_Win64_Cerbu_AB_MTB{
	meta:
		description = "Trojan:Win64/Cerbu.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f b7 47 06 ff c6 48 83 c3 28 3b f0 0f 85 51 ff ff ff 0f b7 c8 41 0f b7 5f 14 45 33 f6 48 83 c3 18 49 03 df 66 85 c9 0f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}