
rule Trojan_BAT_Zusy_SLBC_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SLBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 28 27 00 00 0a 72 75 00 00 70 28 28 00 00 0a 0c 07 08 28 03 00 00 06 72 95 00 00 70 08 28 29 00 00 0a 28 2a 00 00 0a 06 28 2b 00 00 0a 0d 09 8e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}