
rule Trojan_Win64_Doina_MCG_MTB{
	meta:
		description = "Trojan:Win64/Doina.MCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 73 64 67 6e 72 74 72 74 67 00 63 76 62 63 76 62 00 64 66 67 64 65 79 65 72 74 79 00 68 6a 6b 74 79 6a 66 67 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}