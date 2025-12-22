
rule Trojan_BAT_Rozena_CZI_MTB{
	meta:
		description = "Trojan:BAT/Rozena.CZI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 04 00 00 0a 72 01 00 00 70 28 05 00 00 0a 13 0b 12 0b 72 0b 00 00 70 28 06 00 00 0a 72 0f 00 00 70 28 07 00 00 0a 28 08 00 00 0a 13 08 11 08 11 06 28 09 00 00 0a 00 73 0a 00 00 0a 13 09 11 09 6f 0b 00 00 0a 11 08 6f 0c 00 00 0a 00 11 09 6f 0d 00 00 0a 26 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}