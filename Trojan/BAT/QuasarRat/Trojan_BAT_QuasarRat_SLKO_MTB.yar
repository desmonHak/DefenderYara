
rule Trojan_BAT_QuasarRat_SLKO_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.SLKO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 c0 0d 00 70 28 54 09 00 06 0a 1b 8d 14 00 00 01 25 16 72 f1 0e 00 70 a2 25 17 02 a2 25 18 72 8b 0e 00 70 a2 25 19 06 a2 25 1a 72 af 0e 00 70 a2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}