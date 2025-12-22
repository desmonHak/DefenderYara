
rule Trojan_BAT_Zapchast_MK_MTB{
	meta:
		description = "Trojan:BAT/Zapchast.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 04 00 00 06 0a 06 02 7d 02 00 00 04 06 fe 06 05 00 00 06 73 09 00 00 0a 73 0a 00 00 0a 28 0b 00 00 0a 7e 01 00 00 04 2d 11 14 fe 06 03 00 00 06 73 09 00 00 0a 80 01 00 00 04 7e 01 00 00 04 73 0a 00 00 0a 28 0b 00 00 0a 2a } //25
	condition:
		((#a_01_0  & 1)*25) >=25
 
}