
rule Trojan_BAT_Heracles_SLAL_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SLAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 8d 07 00 00 01 13 08 11 08 16 72 01 00 00 70 a2 11 08 0a 72 25 00 00 70 0b 20 00 32 01 00 0c 08 8d 08 00 00 01 0d 07 28 04 00 00 0a 73 05 00 00 0a 13 04 00 11 04 16 73 06 00 00 0a 13 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}