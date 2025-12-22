
rule Trojan_BAT_Marsilia_SLQS_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.SLQS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 08 6f 08 00 00 0a 28 09 00 00 0a a5 01 00 00 1b 0b 38 e2 00 00 00 06 6e 18 6a 33 27 17 8d 01 00 00 1b 0d 7e 01 00 00 04 02 09 16 fe 1c 01 00 00 1b 28 0a 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}