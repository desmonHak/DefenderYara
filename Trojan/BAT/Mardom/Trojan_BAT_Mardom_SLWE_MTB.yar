
rule Trojan_BAT_Mardom_SLWE_MTB{
	meta:
		description = "Trojan:BAT/Mardom.SLWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 e8 38 00 70 72 b0 3c 00 70 d0 89 00 00 01 28 c5 00 00 0a 06 6f 51 01 00 0a 28 51 00 00 06 0b fe 0c 02 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}