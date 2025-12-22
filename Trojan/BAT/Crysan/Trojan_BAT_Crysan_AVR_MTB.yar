
rule Trojan_BAT_Crysan_AVR_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 17 da 13 0d 18 13 0e 2b 1a 11 05 11 0e 11 05 11 0e 17 da 96 11 05 11 0e 18 da 96 d6 9f 11 0e 17 d6 13 0e 11 0e 11 0d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}