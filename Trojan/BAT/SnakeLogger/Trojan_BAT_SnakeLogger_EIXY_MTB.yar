
rule Trojan_BAT_SnakeLogger_EIXY_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.EIXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 07 11 14 11 14 11 14 5a d2 9c 11 14 17 58 13 14 11 14 11 07 8e 69 fe 04 13 15 11 15 2d e1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}