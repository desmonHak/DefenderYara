
rule Trojan_BAT_Perseus_SLDH_MTB{
	meta:
		description = "Trojan:BAT/Perseus.SLDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 2f 00 00 0a 00 07 16 09 16 07 8e 69 08 8e 69 59 28 2f 00 00 0a 00 73 10 00 00 06 13 04 28 30 00 00 0a 11 04 03 06 14 09 08 6f 0a 00 00 06 6f 31 00 00 0a 13 05 11 05 13 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}