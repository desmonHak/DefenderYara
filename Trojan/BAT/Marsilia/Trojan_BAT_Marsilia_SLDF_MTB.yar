
rule Trojan_BAT_Marsilia_SLDF_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.SLDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8e 69 18 59 8d c3 00 00 01 0a 16 0b 18 0c 2b 2d 06 07 06 07 91 03 17 91 61 d2 9c 06 07 06 07 91 1f 18 61 d2 9c 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}