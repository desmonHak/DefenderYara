
rule Trojan_BAT_Barys_SLWC_MTB{
	meta:
		description = "Trojan:BAT/Barys.SLWC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 29 00 00 0a 6f 2a 00 00 0a 08 7e 2f 00 00 0a 6f 30 00 00 0a 07 14 16 8d 03 00 00 01 6f 31 00 00 0a 26 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}