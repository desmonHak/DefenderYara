
rule Trojan_BAT_QuasarRAT_SI_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.SI!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 28 41 05 00 06 0b 28 41 05 00 06 0c 28 d5 00 00 0a 7e 47 01 00 04 6f d7 00 00 0a 0d 08 8e 69 8d 1b 01 00 01 13 04 16 13 05 2b 1e 11 04 11 05 08 11 05 91 09 11 05 09 8e 69 5d 91 61 07 11 05 91 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 32 db } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}