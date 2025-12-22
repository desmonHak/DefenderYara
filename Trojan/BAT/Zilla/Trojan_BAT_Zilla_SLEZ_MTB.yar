
rule Trojan_BAT_Zilla_SLEZ_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SLEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 66 00 00 06 0a 28 32 00 00 06 7e 1b 00 00 04 28 7b 00 00 0a 72 12 17 00 70 28 4f 00 00 0a 28 3d 00 00 06 26 06 28 7b 00 00 0a 72 12 17 00 70 28 4f 00 00 0a 7d 3d 00 00 04 28 75 00 00 0a 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}