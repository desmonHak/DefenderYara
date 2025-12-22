
rule Trojan_BAT_Jalapeno_BU_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 74 6e fe 0c b9 00 6e 61 20 93 01 00 01 6a 5a 6d fe 0e b9 00 11 46 46 fe 0e b8 00 11 46 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}