
rule Trojan_Win64_Fragtor_GVB_MTB{
	meta:
		description = "Trojan:Win64/Fragtor.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c7 a3 fc 0c 09 10 8b 44 24 38 8d 04 50 03 d0 8a 81 34 48 00 00 04 10 30 02 ff 01 47 8b 01 8b 54 24 1c 0f b7 44 45 10 3b f8 0f 8e ab fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}