
rule Trojan_BAT_Zilla_SLKL_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SLKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 16 00 00 0a 72 01 00 00 70 6f 17 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 80 01 00 00 04 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Zilla_SLKL_MTB_2{
	meta:
		description = "Trojan:BAT/Zilla.SLKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 0d 00 00 06 28 0b 00 00 06 7e 01 00 00 04 7e 02 00 00 04 28 07 00 00 06 0a 06 2c 1c 06 8e 69 16 31 16 7e 03 00 00 04 28 2d 00 00 06 0b 07 16 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}