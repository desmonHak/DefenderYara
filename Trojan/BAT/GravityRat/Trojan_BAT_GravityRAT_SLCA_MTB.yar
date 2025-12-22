
rule Trojan_BAT_GravityRAT_SLCA_MTB{
	meta:
		description = "Trojan:BAT/GravityRAT.SLCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 9b 04 00 06 0a 06 03 6f 2e 00 00 0a 73 2f 00 00 0a 28 30 00 00 0a 72 e5 00 00 70 28 31 00 00 0a 7d 4a 02 00 04 28 32 00 00 0a 6f 33 00 00 0a 06 fe 06 9c 04 00 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}