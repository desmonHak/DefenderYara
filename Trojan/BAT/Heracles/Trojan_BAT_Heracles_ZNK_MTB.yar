
rule Trojan_BAT_Heracles_ZNK_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ZNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 19 07 11 19 91 20 fa 00 00 00 61 d2 9c 00 11 19 17 58 13 19 11 19 07 8e 69 fe 04 13 1a 11 1a 2d dc } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}