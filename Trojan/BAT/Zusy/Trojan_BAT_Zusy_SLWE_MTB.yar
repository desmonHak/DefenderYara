
rule Trojan_BAT_Zusy_SLWE_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SLWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 7b 03 00 00 04 06 6c 6f 0d 00 00 0a 00 02 7b 03 00 00 04 17 6f 0e 00 00 0a 00 2b 0d 00 20 e8 03 00 00 28 0f 00 00 0a 00 00 02 7b 02 00 00 04 0b 07 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}