
rule Trojan_BAT_Mardom_BAA_MTB{
	meta:
		description = "Trojan:BAT/Mardom.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 04 1a 5d 2c 03 03 2b 07 03 20 f3 00 00 00 61 b4 0a 2b 00 06 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}