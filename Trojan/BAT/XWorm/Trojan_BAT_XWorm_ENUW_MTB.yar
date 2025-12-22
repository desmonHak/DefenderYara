
rule Trojan_BAT_XWorm_ENUW_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ENUW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 fe 09 00 00 7b de 01 00 04 fe 0c 02 00 fe 0c 02 00 d2 9c 00 fe 0c 02 00 20 01 00 00 00 58 fe 0e 02 00 fe 0c 02 00 20 00 01 00 00 fe 04 fe 0e 03 00 fe 0c 03 00 3a c5 ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}